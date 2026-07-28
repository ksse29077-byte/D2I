#ifndef D2I_ABI_V1_H
#define D2I_ABI_V1_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define D2I_ABI_VERSION_V1 UINT32_C(1)
#define D2I_MEMORY_HOST UINT32_C(0)
#define D2I_BUFFER_READ_ONLY UINT32_C(1)
#define D2I_BUFFER_FLAGS_NONE UINT32_C(0)

typedef uint32_t D2iStatus;

enum {
    D2I_OK = 0,
    D2I_INVALID_ARGUMENT = 1,
    D2I_TIMEOUT = 2,
    D2I_INTERNAL = 3,
    D2I_UNSUPPORTED = 4,
    D2I_BUFFER_TOO_SMALL = 5
};

typedef struct D2iBufferView {
    const uint8_t* ptr;
    uint64_t len;
    uint32_t alignment;
    uint32_t memory_kind;
    uint32_t flags;
    uint32_t reserved;
} D2iBufferView;

typedef struct D2iBufferMut {
    uint8_t* ptr;
    uint64_t len;
    uint64_t capacity;
    uint32_t alignment;
    uint32_t memory_kind;
    uint32_t flags;
    uint32_t reserved;
} D2iBufferMut;

typedef D2iStatus (*D2iInitFn)(
    const D2iBufferView* config,
    void** out_handle
);

typedef D2iStatus (*D2iRunFn)(
    void* handle,
    const D2iBufferView* input,
    D2iBufferMut* output
);

typedef D2iStatus (*D2iResetFn)(void* handle);
typedef void (*D2iDestroyFn)(void* handle);

typedef struct D2iModuleV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    D2iBufferView module_id;
    D2iBufferView module_version;
    D2iInitFn init;
    D2iRunFn run;
    D2iResetFn reset;
    D2iDestroyFn destroy;
} D2iModuleV1;

typedef const D2iModuleV1* (*D2iModuleEntryV1)(void);

typedef D2iStatus (*D2iScoreMatchMasksV1)(
    const uint8_t* match_masks,
    uint64_t item_count,
    uint16_t* scores,
    uint64_t score_capacity
);

/*
 * Optional Phase 7 isolated score-kernel symbol:
 *     D2iStatus d2i_score_match_masks_v1(
 *         const uint8_t*, uint64_t, uint16_t*, uint64_t);
 *
 * Each input byte uses bits 0/1/2 for symptom, error-code, and equipment
 * matches. The output score is 45, 45, and 10 points respectively. All other
 * input bits are invalid. The host owns both arrays.
 */

struct ArrowArray;
struct ArrowSchema;

typedef struct D2iArrowCDataView {
    const struct ArrowArray* array;
    const struct ArrowSchema* schema;
} D2iArrowCDataView;

typedef struct D2iDlpackView {
    void* managed_tensor;
    uint64_t flags;
} D2iDlpackView;

/*
 * Required exported symbol:
 *     const D2iModuleV1* d2i_module_v1(void);
 *
 * Ownership:
 * - The host owns every input and output byte buffer.
 * - A module may mutate only output bytes and D2iBufferMut.len.
 * - A module must not retain a buffer pointer after a call returns.
 * - init creates one opaque handle; destroy releases it exactly once.
 * - init must leave out_handle null when it returns a non-OK status.
 * - Calls for one handle are serialized; modules need not be reentrant.
 * - No panic or foreign exception may cross a function-table call.
 */

#if defined(__cplusplus)
}
#endif

#endif
