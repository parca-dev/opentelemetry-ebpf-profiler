// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Logic for generating return pads from a range symbfile and the executable.

use crate::{debug, disas, objfile, symbfile, AnyError, VirtAddr};
use fallible_iterator::FallibleIterator;
use intervaltree::{Element, IntervalTree};
use smallvec::{smallvec, SmallVec};
use std::{io, mem};

/// Result type shorthand.
pub type Result<T = (), E = Error> = std::result::Result<T, E>;

/// Errors that can occur during return pad generation.
#[non_exhaustive]
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unsupported object file architecture")]
    UnsupportedArch,

    #[error("Unable to locate code section for disassembly")]
    TextSectionNotFound,

    #[error("Symbfile error: {}", .0)]
    Symbfile(#[from] symbfile::Error),

    #[error("Objfile error: {}", .0)]
    Objfile(#[from] objfile::Error),

    #[error("Disassembler error: {}", .0)]
    Disas(#[from] disas::Error),

    #[error(transparent)]
    Other(AnyError),
}

/// Special-casing for the Go start-of-stack function.
///
/// Go [manually pushes] a return address into their `runtime.goexit` function
/// onto the stack. This cannot be detected by our regular logic that merely
/// scans for call instructions and needs special handling.
///
/// On both ARM64 and AMD64 this function consists of only two instructions
/// and the manually calculated return address points to the second instruction.
///
/// [manually pushes]: https://github.com/golang/go/blob/a40404da7/src/runtime/proc.go#L4556
fn go_stack_start_special_case(
    mem: &objfile::MemoryMap<'_>,
    decoder: &dyn disas::InstrDecoder,
    sub_tree: &Vec<symbfile::Range>,
    mut visitor: impl FnMut(symbfile::ReturnPad) -> Result,
) -> Result {
    let outer_func = &sub_tree[0];

    if outer_func.func != "runtime.goexit" {
        return Ok(());
    }

    let Some(code) = mem.slice_for_addr(outer_func.elf_va, u64::from(outer_func.length)) else {
        debug!("Failed to read runtime.goexit memory");
        return Ok(());
    };

    let first_insn = match decoder.decode(outer_func.elf_va, code) {
        Ok(insn) => insn,
        Err(e) => {
            debug!("Failed to decode first instruction in runtime.goexit: {e:?}");
            return Ok(());
        }
    };

    visitor(symbfile::ReturnPad {
        elf_va: outer_func.elf_va + u64::from(first_insn.length) - 1,
        entries: smallvec![symbfile::ReturnPadEntry {
            func: outer_func.func.clone(),
            file: outer_func.file.clone(),
            line: None,
            discriminator: 0,
            start_line: outer_func.start_line,
        }],
    })
}

fn process_tree(
    mem: &objfile::MemoryMap<'_>,
    decoder: &dyn disas::InstrDecoder,
    sub_tree: Vec<symbfile::Range>,
    mut visitor: impl FnMut(symbfile::ReturnPad) -> Result,
) -> Result<()> {
    go_stack_start_special_case(mem, decoder, &sub_tree, &mut visitor)?;

    // Collect return pads by disassembling all relevant code.
    let mut ret_pads = Vec::new();
    'outer: for range in &sub_tree {
        if range.depth != 0 {
            // The top level (depth = 0) ranges must cover the ranges of all
            // children. It is thus unnecessary to inspect the children here.
            // In fact, doing so would even be incorrect and result in duplicate
            // records to be inserted.
            continue;
        }

        let Some(code) = mem.slice_for_addr(range.elf_va, range.length as u64) else {
            debug!(
                "Unable to map {:x?} to code section, skipping.",
                range.va_range()
            );
            continue;
        };

        use disas::Error as DE;
        let mut instr_iter = disas::decode_all(decoder, range.elf_va, code);
        while let Some(instr) = match instr_iter.next() {
            Ok(x) => x,
            Err(DE::TruncatedInstruction(addr) | DE::InvalidInstruction(addr)) => {
                debug!("Unable to decode instruction @ {:#08X}", addr);
                continue 'outer;
            }
            Err(other) => return Err(Error::Disas(other)),
        } {
            if instr.is_call {
                let call_va = instr.addr;
                let ret_pad_va = instr.addr + instr.length as VirtAddr;
                ret_pads.push((call_va, ret_pad_va));
            }
        }
    }

    // If no return pads were found, we are done here.
    if ret_pads.is_empty() {
        return Ok(());
    }

    // Construct interval tree to allow for quick lookups of all inline
    // levels that belong to our return pads.
    let tree = IntervalTree::from_iter(sub_tree.into_iter().map(|rng| Element {
        range: rng.va_range(),
        value: rng,
    }));

    // Look up and emit inline trace for each return pad.
    'outer: for (call_va, ret_pad_va) in ret_pads {
        // Use the address of the call instruction to create the trace.
        let mut matches: Vec<_> = tree.query_point(call_va).collect();

        // Need to process matches in ascending depth order.
        matches.sort_unstable_by_key(|x| x.value.depth);

        let mut entries = SmallVec::new();
        let mut iter = matches.iter().peekable();
        while let Some(Element { value: cur, .. }) = iter.next() {
            let (file, line, discriminator) = if let Some(Element { value: next, .. }) = iter.peek()
            {
                if cur.depth + 1 != next.depth {
                    debug!(
                        "Detected hole in inline chain for call @ {:#08X}, skipping",
                        call_va
                    );
                    continue 'outer;
                }

                // For the first n-1 non-leaf entries, use the call_X fields.
                (&next.call_file, next.call_line, next.call_discriminator)
            } else {
                // For the leaf record, resolve the line using the line table.
                let entry = cur.line_table_entry_for_va(call_va);
                (
                    &cur.file,
                    entry.map(|x| x.line_number),
                    entry.map_or(0, |x| x.discriminator),
                )
            };

            entries.push(symbfile::ReturnPadEntry {
                func: cur.func.clone(),
                file: file.clone(),
                line,
                discriminator,
                // The `line` above always falls within `cur`'s body (either its
                // call site into the next inline frame, or — for the leaf — the
                // instruction itself), so the right anchor is `cur`'s own
                // definition line.
                start_line: cur.start_line,
            });
        }

        // If we didn't find any matches to construct a trace from,
        // then there is no point in writing a record.
        if entries.is_empty() {
            continue;
        }

        // Return pads are stored with a negative offset of 1 to be consistent
        // with the non-leaf addresses sent by the host agent. Check `proto/symbfile/symbfile.proto`
        // documentation for more information.
        visitor(symbfile::ReturnPad {
            elf_va: ret_pad_va - 1,
            entries,
        })?;
    }

    Ok(())
}

/// Extract return pads by combining the given ranges and the corresponding
/// executable, writing them into the given output stream in the form of a
/// return pad symbfile.
pub fn create_retpad_symbfile(
    exec_path: &std::path::Path,
    range_reader: impl io::Read,
    retpad_writer: impl io::Write,
) -> Result {
    let mut writer = symbfile::Writer::new(retpad_writer)?;

    let obj = objfile::File::load(exec_path)?;
    let obj = obj.parse()?;

    let ranges = symbfile::Reader::new(range_reader)?
        .filter_map(|msg| match msg {
            symbfile::Record::Range(range) => Ok(Some(range)),
            _other => Ok(None),
        })
        .map_err(Error::Symbfile);

    extract_retpads(&obj, ranges, |rp| writer.write(rp).map_err(Error::Symbfile))?;

    writer.finalize()?;
    Ok(())
}

/// Extract return pads by combining the given range file IO reader and
/// the corresponding executable.
///
/// The `visitor` callback is invoked for every return pad in the executable.
/// Returning an error will abort further execution and return early.
pub fn extract_retpads(
    executable: &objfile::Reader<'_>,
    mut ranges: impl FallibleIterator<Item = symbfile::Range, Error = Error>,
    mut visitor: impl FnMut(symbfile::ReturnPad) -> Result,
) -> Result {
    let mem = executable.memory_map()?;

    // Create type-erased instruction decoder.
    let decoder: Box<dyn disas::InstrDecoder> = match executable.arch() {
        Some(objfile::Arch::X86_64) => Box::<disas::Amd64InstrDecoder>::default(),
        Some(objfile::Arch::Aarch64) => Box::<disas::Aarch64InstrDecoder>::default(),
        None => return Err(Error::UnsupportedArch),
    };

    let mut tree_buf = Vec::new();
    while let Some(range) = ranges.next()? {
        // The symbfile range files contain the flattened inline tree in
        // pre-order depth-first search order. This means that to collect
        // all children of a particular sub-tree we simply need to check
        // whether the depth field returns to 0 at some point.
        if range.depth == 0 && !tree_buf.is_empty() {
            let sub_tree = mem::replace(&mut tree_buf, vec![range]);
            process_tree(&mem, &*decoder, sub_tree, &mut visitor)?;
        } else {
            tree_buf.push(range);
        }
    }

    // Process final batch.
    if !tree_buf.is_empty() {
        process_tree(&mem, &*decoder, tree_buf, &mut visitor)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::testdata;
    use std::fs::File;
    use std::io::{Seek as _, SeekFrom};

    #[test]
    fn translation() {
        let exec_path = testdata("inline-no-tco");
        let range_symbfile = File::open(testdata("inline-no-tco.ranges.symbfile")).unwrap();
        let mut retpad_symbfile = tempfile::tempfile().unwrap();
        create_retpad_symbfile(&exec_path, range_symbfile, &mut retpad_symbfile).unwrap();
        retpad_symbfile.seek(SeekFrom::Start(0)).unwrap();

        let mut reader = symbfile::Reader::new(retpad_symbfile).unwrap();

        // The message order in return pad symbfiles is undefined: read all and sort.
        let mut records = Vec::<symbfile::ReturnPad>::new();
        while let Some(msg) = reader.read().unwrap() {
            records.push(match msg {
                symbfile::Record::ReturnPad(pad) => pad,
                _ => panic!("unexpected record type"),
            });
        }
        records.sort_unstable_by_key(|x| x.elf_va);
        let mut record_iter = records.iter();

        // Reference data created by scrolling through disassembly in IDA,
        // looking for any calls in functions with DWARF info.
        //
        // Line numbers are those of `inline.c` as it was when the test binaries
        // were built. It has since gained a 3-line license header, so add 3 to
        // find them in the checked-in copy.

        // .text:000648 6A 00 00 94  BL    a
        // .text:00064C 00 00 00 90+ ADRL  X0, aHello ; "hello!"

        let a_call = record_iter.next().unwrap();
        let inline_file =
            Some("/media/share/Development/prodfiler/libpf-rs/testdata/inline.c".to_owned());
        assert_eq!(a_call.elf_va, 0x64c - 1);
        assert_eq!(a_call.entries.len(), 1);
        assert_eq!(a_call.entries[0].func, "main");
        assert_eq!(a_call.entries[0].file, inline_file.clone());
        assert_eq!(a_call.entries[0].line, Some(39));
        // `main` is defined at line 38 (`DW_AT_decl_line`).
        assert_eq!(a_call.entries[0].start_line, Some(38));

        // .text:000654 F7 FF FF 97  BL    .puts
        // .text:000658 00 00 80 52  MOV   W0, #0
        let puts_call_in_main = record_iter.next().unwrap();
        assert_eq!(puts_call_in_main.elf_va, 0x658 - 1);
        assert_eq!(puts_call_in_main.entries.len(), 5);

        // Each frame's `line` is an absolute line within that frame's own
        // function; `start_line` is that same function's definition line, so
        // the two together give a stable per-frame anchor for AutoFDO.
        assert_eq!(puts_call_in_main.entries[0].func, "main");
        assert_eq!(puts_call_in_main.entries[0].file, inline_file.clone());
        assert_eq!(puts_call_in_main.entries[0].line, Some(40));
        assert_eq!(puts_call_in_main.entries[0].start_line, Some(38));

        assert_eq!(puts_call_in_main.entries[1].func, "a_inline");
        assert_eq!(puts_call_in_main.entries[1].file, inline_file.clone());
        assert_eq!(puts_call_in_main.entries[1].line, Some(35));
        assert_eq!(puts_call_in_main.entries[1].start_line, Some(34));

        assert_eq!(puts_call_in_main.entries[2].func, "b_inline");
        assert_eq!(puts_call_in_main.entries[2].file, inline_file.clone());
        assert_eq!(puts_call_in_main.entries[2].line, Some(31));
        assert_eq!(puts_call_in_main.entries[2].start_line, Some(30));

        assert_eq!(puts_call_in_main.entries[3].func, "c_inline");
        assert_eq!(puts_call_in_main.entries[3].file, inline_file.clone());
        assert_eq!(puts_call_in_main.entries[3].line, Some(27));
        assert_eq!(puts_call_in_main.entries[3].start_line, Some(26));

        assert_eq!(puts_call_in_main.entries[4].func, "d_inline");
        assert_eq!(puts_call_in_main.entries[4].file, inline_file.clone());
        assert_eq!(puts_call_in_main.entries[4].line, Some(23));
        // d_inline: defined at line 22, but the return-pad line is 23.
        assert_eq!(puts_call_in_main.entries[4].start_line, Some(22));

        // .text:0007B0 A0 FF FF 97  BL   .puts
        // .text:0007B4 FD 7B C1 A8  LDP  X29, X30, [SP+var_s0],#0x10
        let puts_call_in_d = record_iter.next().unwrap();
        assert_eq!(puts_call_in_d.elf_va, 0x7b4 - 1);
        assert_eq!(puts_call_in_d.entries.len(), 1);
        assert_eq!(puts_call_in_d.entries[0].func, "d");
        assert_eq!(puts_call_in_d.entries[0].file, inline_file.clone());
        assert_eq!(puts_call_in_d.entries[0].line, Some(7));
        assert_eq!(puts_call_in_d.entries[0].start_line, Some(6));

        // .text:0007C8 F6 FF FF 97  BL    d
        // .text:0007CC FD 7B C1 A8  LDP   X29, X30, [SP+var_s0],#0x10
        let d_call_in_c = record_iter.next().unwrap();
        assert_eq!(d_call_in_c.elf_va, 0x7cc - 1);
        assert_eq!(d_call_in_c.entries.len(), 1);
        assert_eq!(d_call_in_c.entries[0].func, "c");
        assert_eq!(d_call_in_c.entries[0].file, inline_file.clone());
        assert_eq!(d_call_in_c.entries[0].line, Some(11));
        assert_eq!(d_call_in_c.entries[0].start_line, Some(10));

        // .text:00007DC F9 FF FF 97  BL    c
        // .text:00007E0 FD 7B C1 A8  LDP   X29, X30, [SP+var_s0],#0x10
        let c_call_in_b = record_iter.next().unwrap();
        assert_eq!(c_call_in_b.elf_va, 0x7e0 - 1);
        assert_eq!(c_call_in_b.entries.len(), 1);
        assert_eq!(c_call_in_b.entries[0].func, "b");
        assert_eq!(c_call_in_b.entries[0].file, inline_file.clone());
        assert_eq!(c_call_in_b.entries[0].line, Some(15));
        assert_eq!(c_call_in_b.entries[0].start_line, Some(14));

        // .text:0007F8 F7 FF FF 97  BL    b
        // .text:0007FC FD 7B C1 A8  LDP   X29, X30, [SP+var_s0],#0x10
        let b_call_in_a = record_iter.next().unwrap();
        assert_eq!(b_call_in_a.elf_va, 0x7fc - 1);
        assert_eq!(b_call_in_a.entries.len(), 1);
        assert_eq!(b_call_in_a.entries[0].func, "a");
        assert_eq!(b_call_in_a.entries[0].file, inline_file.clone());
        assert_eq!(b_call_in_a.entries[0].line, Some(19));
        assert_eq!(b_call_in_a.entries[0].start_line, Some(18));

        assert!(record_iter.next().is_none());
    }

    /// Return pads carry the discriminators that tell apart calls on the same
    /// line: call site discriminators for non-leaf frames, line table
    /// discriminators for the leaf frame.
    #[test]
    fn discriminators() {
        use crate::symbconv::{dwarf::Extractor, RangeExtractor as _};

        let obj = objfile::File::load(&testdata("discriminators")).unwrap();
        let obj = obj.parse().unwrap();
        let dw = crate::dwarf::Sections::load(&obj).unwrap();
        let mut ranges = Vec::new();
        Extractor::new(&dw)
            .extract(&mut |range| {
                ranges.push(range);
                Ok(())
            })
            .unwrap();

        let mut pads = Vec::new();
        let ranges = fallible_iterator::convert(ranges.into_iter().map(Ok));
        extract_retpads(&obj, ranges, |pad| {
            pads.push(pad);
            Ok(())
        })
        .unwrap();

        let entries = |elf_va| {
            let pad = pads.iter().find(|x| x.elf_va == elf_va).unwrap();
            let entries = pad.entries.iter();
            entries
                .map(|x| (x.func.as_str(), x.line.unwrap(), x.discriminator))
                .collect::<Vec<_>>()
        };

        // The two inlined calls to `say` on line 22, each calling `puts`.
        //
        // 108f0:  bl  0x10a70 <puts@plt>
        // 108f4:  ldp x29, x30, [sp], #0x10
        assert_eq!(entries(0x108f4 - 1), [("pick", 22, 2), ("say", 10, 0)]);
        // 10904:  bl  0x10a70 <puts@plt>
        // 10908:  ldp x29, x30, [sp], #0x10
        assert_eq!(entries(0x10908 - 1), [("pick", 22, 4), ("say", 10, 0)]);

        // Call to `pick` in the body of the `for` loop on line 27.
        //
        // 10930:  bl  0x108dc <pick>
        // 10934:  add w20, w20, #0x1
        assert_eq!(entries(0x10934 - 1), [("main", 27, 4)]);
    }
}
