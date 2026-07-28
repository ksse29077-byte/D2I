#include "d2i_abi_v1.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

_Static_assert(sizeof(void*) == 8, "D2I ABI v1 requires a 64-bit target");
_Static_assert(sizeof(D2iBufferView) == 32, "D2iBufferView layout mismatch");
_Static_assert(offsetof(D2iBufferView, flags) == 24, "D2iBufferView offset mismatch");
_Static_assert(sizeof(D2iBufferMut) == 40, "D2iBufferMut layout mismatch");
_Static_assert(offsetof(D2iBufferMut, flags) == 32, "D2iBufferMut offset mismatch");
_Static_assert(sizeof(D2iModuleV1) == 104, "D2iModuleV1 layout mismatch");
_Static_assert(offsetof(D2iModuleV1, init) == 72, "D2iModuleV1 offset mismatch");

typedef struct FixtureHandle {
    uint64_t runs;
} FixtureHandle;

static D2iStatus fixture_init(
    const D2iBufferView* config,
    void** out_handle
) {
    (void)config;
    if (out_handle == NULL) {
        return D2I_INVALID_ARGUMENT;
    }
    FixtureHandle* handle = (FixtureHandle*)calloc(1, sizeof(FixtureHandle));
    if (handle == NULL) {
        return D2I_INTERNAL;
    }
    *out_handle = handle;
    return D2I_OK;
}

static D2iStatus fixture_run(
    void* raw_handle,
    const D2iBufferView* input,
    D2iBufferMut* output
) {
    if (raw_handle == NULL || input == NULL || output == NULL) {
        return D2I_INVALID_ARGUMENT;
    }
    if (input->ptr == NULL || output->ptr == NULL) {
        return D2I_INVALID_ARGUMENT;
    }
    if (input->len > output->capacity) {
        output->len = input->len;
        return D2I_BUFFER_TOO_SMALL;
    }
    for (uint64_t index = 0; index < input->len; ++index) {
        output->ptr[index] = (uint8_t)toupper((unsigned char)input->ptr[index]);
    }
    output->len = input->len;
    ((FixtureHandle*)raw_handle)->runs += 1;
    return D2I_OK;
}

static D2iStatus fixture_reset(void* raw_handle) {
    if (raw_handle == NULL) {
        return D2I_INVALID_ARGUMENT;
    }
    ((FixtureHandle*)raw_handle)->runs = 0;
    return D2I_OK;
}

static void fixture_destroy(void* raw_handle) {
    free(raw_handle);
}

static const uint8_t MODULE_ID[] = "c-uppercase-fixture";
static const uint8_t MODULE_VERSION[] = "1.0.0";

static const D2iModuleV1 MODULE = {
    D2I_ABI_VERSION_V1,
    (uint32_t)sizeof(D2iModuleV1),
    {
        MODULE_ID,
        sizeof(MODULE_ID) - 1,
        1,
        D2I_MEMORY_HOST,
        D2I_BUFFER_READ_ONLY,
        0
    },
    {
        MODULE_VERSION,
        sizeof(MODULE_VERSION) - 1,
        1,
        D2I_MEMORY_HOST,
        D2I_BUFFER_READ_ONLY,
        0
    },
    fixture_init,
    fixture_run,
    fixture_reset,
    fixture_destroy
};

#if defined(_WIN32)
__declspec(dllexport)
#endif
const D2iModuleV1* d2i_module_v1(void) {
    return &MODULE;
}
