# How the LuaJIT Unwinder Works

This is an attempt (as yet unfinished) to explain enough about LuaJIT internals to understand the Polar Signals LuaJIT unwinder.

Details are only given for aarch64, because it's a bit easier (IMO) to understand than x86-64 assembly. However, the situation for x86-64 is conceptually identical.

## Executing Lua Code

### Bytecode

Initially, all Lua code is compiled into un-JITted bytecode. The behavior of each bytecode is defined (in a home-grown macro assembler language) in [vm_arm64.dasc](https://github.com/luajit/luajit/blob/659a6169/src/vm_arm64.dasc). Every instruction ends by executing the [`ins_next`](https://github.com/luajit/luajit/blob/659a6169/src/vm_arm64.dasc#L229-L237) macro, which loads the next instruction from the virtual program counter and decodes it into an opcode and operands. It then looks up the handler for the opcode in a global dispatch table, and jumps to it. An archived list of operands can be found [on the WayBack Machine](https://web.archive.org/web/20220607041223/http://wiki.luajit.org/Bytecode-2.0).

### The Stack

Lua code does not use the native callstack. Instead, a virtual callstack is maintained. Each element of the stack is a 64-bit [`TValue`](https://github.com/luajit/luajit/blob/659a6169/src/lj_obj.h#L174-L174), which can contain various types of data, most importantly a number or a reference to a heap object.

Many bytecode instructions operate on the stack. For example, `ADDVV 0 1 2` (**Add** **V**ariable **V**ariable) adds the numbers at stack slots 1 and 2, and stores the result in stack slot 0. All these slot numbers are relative to the base of the currently-executing function; that is, the beginning of its stack frame.

The [`lua_State`](https://github.com/luajit/luajit/blob/659a6169/src/lj_obj.h#L690-L705) object; that is, the per-thread top-level state, points to various important points in the stack:

* `stack` points to the beginning of the stack;
* `top` points one past the end of the stack;
* `base` points to the base of the currently-executing function; that is, the beginning of its stack frame;
* `maxstack` points to the last available slot in the stack.

`base` is always preceded by two elements: the (virtual) return address, and a reference to the function being executed. Although these are meaningless in the top-level context where no function has yet been invoked, certain internal macros rely on the assumption that it is always possible to read two elements behind `base` in the stack, and so when a new `lua_State` is initialized, its stack always starts with two elements: note the two invocations of `st++` in [`stack_init`](https://github.com/luajit/luajit/blob/659a6169/src/lj_state.c#L168-L180).

Note that these values are updated only when reentering C code. Within Lua code, the base is held in the `BASE` register (an alias for `x19`), and the top is not needed (it can be recomputed when entering C code from the current base and number of arguments). 

### Function Calls (Lua-to-Lua)

Lua-to-Lua calls work by emitting the [`CALL`](https://github.com/luajit/luajit/blob/659a6169/src/vm_arm64.dasc#L3453-L3463) bytecode or one of its variants. The basic call convention is as follows.

| Call Stack          |
|---------------------|
| argn                |
| ...                 |
| arg1                |
| *empty*             |
| CALLEE              |
| ... (rest of stack) |

That is, the caller must save the callee function, followed by an empty slot (its contents don't matter; it will be overwritten with the current program counter), followed by its arguments, at the top of the stack, before executing `CALL`. The `CALL` instruction, along with the [`call dispatch macros`](https://github.com/luajit/luajit/blob/659a6169/src/vm_arm64.dasc#L256-L272) it invokes, save the current program counter in the empty stack slot, update the `BASE` pointer to point to the new stack base, decode the first bytecode instruction in the function and jump to its handler.

This will typically be a "function header" instruction, of which there are [several variants](https://web.archive.org/web/20220607041223/http://wiki.luajit.org/Bytecode-2.0#function-headers). But the basic idea is that the function header is responsible for

* For interpreted functions, checking if the function is "hot" and needs to be JITted, and
* Ensuring that the stack contains enough space for all the values that the function may store in its frame.

In any case, after doing these and some other bookkeeping tasks, the header jumps to the next instruction and execution proceeds as normal.

Lua-to-Lua returns are handled by [`BC_RET`](https://github.com/luajit/luajit/blob/659a6169/src/vm_arm64.dasc#L3700-L3700) and its variants. They restore the base and program counters appropriately, (TODO: explain how base is restored by extracting the offset from the call instruction) and write the return values to the top of the stack.

## The C-to-Lua interface

There are several ways C code can call Lua code, and vice versa.

### `lua_call` and `lua_pcall`

These functions are used to call a Lua function from C code. Their behavior is identical except that `lua_pcall` sets up a "protected" context that enables error handling: for our purposes of stack unwinding, this difference is irrelevant, so we will discuss only `lua_call` here.

The C caller calls a Lua function by pushing the function to the stack, followed by its arguments, and then invoking `lua_call`. At the end of that call, the function and arguments will have been popped, and the return values pushed onto the stack. For example, if `fib` is a function defined in Lua and we want to call `fib(40)` and print the results, we would execute the following code:

``` c
// Get the global object called `fib` and push it onto the stack
lua_getglobal(L, "fib");
// Push the number 40 onto the stack
lua_pushinteger(L, 40);
// Call the function
lua_call(
     L,
     // 1 argument
     1,
     // Expecting 1 return value
     1);
// Get the result from position -1 (that is, the top of the stack)
long long result = (long long)lua_tointeger(L, -1);
// Print it
printf("%lld\n", result);
// Pop the result, leaving our stack in the same state it was before the call sequence
lua_pop(L, 1);
```

The [`lua_call`](https://github.com/luajit/luajit/blob/659a6169/src/lj_api.c#L1112-L1118) API function moves all the arguments up one position on the virtual stack in order to leave an empty slot. Recall that in Lua-to-Lua calls, this empty slot is used to store the virtual return address. We have no virtual return address here (since we are coming from C code, not Lua), but keeping the stack layout consistent simplifies the operation of the interpreter. It then invokes the [`vm_call`](https://github.com/luajit/luajit/blob/659a6169/src/vm_arm64.dasc#L555-L555) interpreter subroutine.

The `vm_call` code sets up a new physical stack frame (that is, on the actual machine stack, not the virtual Lua stack). The size of this stack frame `CFRAME_SPACE` bytes; this is 208 on aarch64, and saves various caller-saved registers to it (which are then allowed to be clobbered by the interpreter code during Lua execution). It also saves the frame pointer and physical return address, like any normal C-to-C call. It then pushes the current stack pointer onto a linked list of C frames maintained in the top-level lua_State, and stores some useful metadata (the "frame type" and size of the new frame in the Lua virtual stack) in the otherwise-unneeded virtual return address stack slot, and then begins executing the bytecode of the Lua function.

When the Lua function returns, the `BC_RET` instruction (or a variant) is able to detect from the frame type metadata stored in the return address slot that it is not returning to a normal Lua frame, and jumps into the [`vm_return`](https://github.com/luajit/luajit/blob/659a6169/src/vm_arm64.dasc#L388-L388) interpreter subroutine. This subroutine is the inverse of `vm_call`: it resets `L->base` and `L->top` to appropriate values, pops the physical stack frame restoring all the saved registers, and executes a return instruction to go back to C code.

### `lua_CFunction`s and `lua_cpcall`

TODO

### Lua-to-C FFI

TODO

## Putting it All Together: How Our Unwinder Unwinds

TODO
