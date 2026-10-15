// Links a program against a GIMCore.xcframework slice (CI xcframework job).
#include "GIMCoreFFI.h"

int main(void) {
    RustCallStatus status = {0};
    RustBuffer version = uniffi_gim_core_fn_func_core_version(&status);
    return status.code != 0 || version.len == 0;
}
