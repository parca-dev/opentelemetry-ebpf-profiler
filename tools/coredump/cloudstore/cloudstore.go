// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// cloudstore provides access to the cloud based storage used in the tests.
package cloudstore // import "go.opentelemetry.io/ebpf-profiler/tools/coredump/cloudstore"

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// moduleStoreRegion defines the S3 bucket OCI region.
const moduleStoreRegion = "us-sanjose-1"

// moduleStoreObjectNamespace defines the S3 bucket OCI object name space.
const moduleStoreObjectNamespace = "axtwf1hkrwcy"

// modulePublicReadUrl defines the S3 bucket OCI public read only base path.
//
//nolint:lll
const modulePublicReadURL = "sm-wftyyzHJkBghWeexmK1o5ArimNwZC-5eBej5Lx4e46sLVHtO_y7Zf7FZgoIu_/n/axtwf1hkrwcy"

// moduleStoreS3Bucket defines the S3 bucket used for the module store.
const moduleStoreS3Bucket = "ebpf-profiling-coredumps"

// gcsBucket defines the public GCS bucket used as an alternative module store.
const gcsBucket = "parca-coredump-artifacts"

// gcsEndpoint is the GCS S3-compatible XML API endpoint.
const gcsEndpoint = "https://storage.googleapis.com"

// GCSBucket returns the name of the public GCS module store bucket.
func GCSBucket() string {
	return gcsBucket
}

// GCSPublicReadURL returns the base URL used to anonymously read objects from
// the public GCS module store bucket.
func GCSPublicReadURL() string {
	return fmt.Sprintf("%s/%s/", gcsEndpoint, gcsBucket)
}

// GCSClient returns an S3 client configured to talk to GCS via its
// S3-compatible XML API. Credentials are loaded from the default AWS
// credential chain (e.g. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY set to a
// GCS HMAC key pair).
func GCSClient() (*s3.Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.Region = "auto"
		o.BaseEndpoint = aws.String(gcsEndpoint)
		o.UsePathStyle = true
		// GCS's S3-compatible XML API is incompatible with two aws-sdk-go-v2
		// defaults, both of which manifest as SignatureDoesNotMatch:
		//
		//  1. Since service/s3 v1.73.0 the SDK computes CRC32 checksums by
		//     default and signs the resulting x-amz-checksum-* headers on
		//     uploads. GCS does not expect them. Reverting to "when required"
		//     restores the pre-v1.73.0, GCS-compatible behavior.
		//     See https://github.com/longhorn/longhorn/issues/12676.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		//  2. The SDK adds and SigV4-signs an "Accept-Encoding: identity"
		//     header, but GCS rewrites Accept-Encoding server-side before it
		//     recomputes the signature, so the signatures no longer match.
		//     (The SDK also signs amz-sdk-invocation-id / amz-sdk-request, but
		//     GCS passes those through unchanged, so they don't need removing.)
		//     There is no client option to exclude a header from signing, so
		//     drop Accept-Encoding from every request just before signing, as in
		//     https://github.com/aws/aws-sdk-go-v2/issues/1816#issuecomment-1927281540.
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Finalize.Insert(
				middleware.FinalizeMiddlewareFunc("StripAcceptEncodingForGCS",
					func(ctx context.Context, in middleware.FinalizeInput,
						next middleware.FinalizeHandler) (middleware.FinalizeOutput,
						middleware.Metadata, error) {
						if req, ok := in.Request.(*smithyhttp.Request); ok {
							req.Header.Del("Accept-Encoding")
						}
						return next.HandleFinalize(ctx, in)
					}),
				"Signing", middleware.Before)
		})
	}), nil
}

func PublicReadURL() string {
	return fmt.Sprintf("https://%s.objectstorage.%s.oci.customer-oci.com/p/%s/b/%s/o/",
		moduleStoreObjectNamespace, moduleStoreRegion, modulePublicReadURL, moduleStoreS3Bucket)
}

func ModulestoreS3Bucket() string {
	return moduleStoreS3Bucket
}

func Client() (*s3.Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		baseEndpoint := fmt.Sprintf("https://%s.compat.objectstorage.%s.oraclecloud.com/",
			moduleStoreObjectNamespace, moduleStoreRegion)
		o.Region = moduleStoreRegion
		o.BaseEndpoint = aws.String(baseEndpoint)
		o.UsePathStyle = true
	}), nil
}
