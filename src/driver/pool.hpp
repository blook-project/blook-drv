#pragma once
#include <ntifs.h>

// Every pool allocation the driver makes carries a benign, Windows-looking tag.
//
// A pool scanner (poolmon, or a driver that walks the pool headers) attributes
// an allocation to a tag; a project-specific tag such as 'bloK' is a one-line
// detection. The tag is chosen once here and used from the first allocation, so
// there is no post-hoc header rewriting (which is racy against the allocator
// and itself detectable). trace_scan reports this tag so an e2e test can verify
// what a scanner would see.
//
// 'MmSt' is the tag the memory manager uses for section/page-table backing; on
// a machine with real memory pressure it appears constantly, so one more
// allocation of that tag is unremarkable. The value is the little-endian
// encoding of the four ASCII bytes.
namespace blook {

inline constexpr ULONG pool_tag = 'tSmM';

}  // namespace blook
