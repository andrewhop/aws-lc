// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#if defined(BORINGSSL_FIPS) && defined(OPENSSL_WINDOWS)
#include <stdio.h>
#include <process.h>

extern void BORINGSSL_bcm_power_on_self_test(void);
extern void rand_thread_state_clear_all(void);

int WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{
  // Perform actions based on the reason for calling.
  switch( fdwReason )
  {
    case DLL_PROCESS_ATTACH:
      // Initialize once for each new process.
      // Return FALSE to fail DLL load.
      fprintf(stderr, "DLL_PROCESS_ATTACH called.\n");
      BORINGSSL_bcm_power_on_self_test();
      break;

    case DLL_THREAD_ATTACH:
      // Do thread-specific initialization.
      fprintf(stderr, "DLL_THREAD_ATTACH called.\n");

      break;

    case DLL_THREAD_DETACH:
      // Do thread-specific cleanup.
      fprintf(stderr, "DLL_THREAD_DETACH called.\n");

      break;

    case DLL_PROCESS_DETACH:
      // Perform any necessary cleanup.
      fprintf(stderr, "DLL_PROCESS_DETACH called.\n");
      rand_thread_state_clear_all();
      break;
  }
  return 1;  // Successful DLL_PROCESS_ATTACH.
}

#endif
