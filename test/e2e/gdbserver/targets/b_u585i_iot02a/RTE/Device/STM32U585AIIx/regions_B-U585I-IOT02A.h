#ifndef REGIONS_B_U585I_IOT02A_H
#define REGIONS_B_U585I_IOT02A_H


//-------- <<< Use Configuration Wizard in Context Menu >>> --------------------
//------ With VS Code: Open Preview for Configuration Wizard -------------------

// <n> Auto-generated using information from packs
// <i> Device Family Pack (DFP):   Keil::STM32U5xx_DFP@3.2.0
// <i> Board Support Pack (BSP):   Keil::B-U585I-IOT02A_BSP@3.0.0

// <h> ROM Configuration
// =======================
// <h> __ROM0 (is rx memory: Flash_NS from DFP)
//   <o> Base address <0x0-0xFFFFFFFF:8>
//   <i> Defines base address of memory region. Default: 0x08000000
//   <i> Contains Startup and Vector Table
#define __ROM0_BASE 0x08000000
//   <o> Region size [bytes] <0x0-0xFFFFFFFF:8>
//   <i> Defines size of memory region. Default: 0x00200000
#define __ROM0_SIZE 0x00200000
// </h>

// <h> __ROM1 (unused)
//   <o> Base address <0x0-0xFFFFFFFF:8>
//   <i> Defines base address of memory region.
#define __ROM1_BASE 0x0
//   <o> Region size [bytes] <0x0-0xFFFFFFFF:8>
//   <i> Defines size of memory region.
#define __ROM1_SIZE 0x0
// </h>

// <h> __ROM2 (unused)
//   <o> Base address <0x0-0xFFFFFFFF:8>
//   <i> Defines base address of memory region.
#define __ROM2_BASE 0x0
//   <o> Region size [bytes] <0x0-0xFFFFFFFF:8>
//   <i> Defines size of memory region.
#define __ROM2_SIZE 0x0
// </h>

// <h> __ROM3 (unused)
//   <o> Base address <0x0-0xFFFFFFFF:8>
//   <i> Defines base address of memory region.
#define __ROM3_BASE 0x0
//   <o> Region size [bytes] <0x0-0xFFFFFFFF:8>
//   <i> Defines size of memory region.
#define __ROM3_SIZE 0x0
// </h>

// </h>

// <h> RAM Configuration
// =======================
// <h> __RAM0 (is rwx memory: SRAM1_NS+SRAM2_NS+SRAM3_NS from DFP)
//   <o> Base address <0x0-0xFFFFFFFF:8>
//   <i> Defines base address of memory region. Default: 0x20000000
//   <i> Contains uninitialized RAM, Stack, and Heap
#define __RAM0_BASE 0x20000000
//   <o> Region size [bytes] <0x0-0xFFFFFFFF:8>
//   <i> Defines size of memory region. Default: 0x000C0000
#define __RAM0_SIZE 0x000C0000
// </h>

// <h> __RAM1 (is rwx memory: SRAM4_NS from DFP)
//   <o> Base address <0x0-0xFFFFFFFF:8>
//   <i> Defines base address of memory region. Default: 0x28000000
#define __RAM1_BASE 0x28000000
//   <o> Region size [bytes] <0x0-0xFFFFFFFF:8>
//   <i> Defines size of memory region. Default: 0x00004000
#define __RAM1_SIZE 0x00004000
// </h>

// <h> __RAM2 (unused)
//   <o> Base address <0x0-0xFFFFFFFF:8>
//   <i> Defines base address of memory region.
#define __RAM2_BASE 0x0
//   <o> Region size [bytes] <0x0-0xFFFFFFFF:8>
//   <i> Defines size of memory region.
#define __RAM2_SIZE 0x0
// </h>

// <h> __RAM3 (unused)
//   <o> Base address <0x0-0xFFFFFFFF:8>
//   <i> Defines base address of memory region.
#define __RAM3_BASE 0x0
//   <o> Region size [bytes] <0x0-0xFFFFFFFF:8>
//   <i> Defines size of memory region.
#define __RAM3_SIZE 0x0
// </h>

// </h>

// <h> Stack / Heap Configuration
//   <o0> Stack Size (in Bytes) <0x0-0xFFFFFFFF:8>
//   <o1> Heap Size (in Bytes) <0x0-0xFFFFFFFF:8>
#define __STACK_SIZE 0x00000200
#define __HEAP_SIZE 0x00000C00
// </h>

// <n> Resources that are not allocated to linker regions
// <i> rx ROM:   Flash_S from DFP:         BASE: 0x0C000000  SIZE: 0x00200000
// <i> rwx RAM:  SRAM1_S from DFP:         BASE: 0x30000000  SIZE: 0x00030000
// <i> rwx RAM:  SRAM2_S from DFP:         BASE: 0x30030000  SIZE: 0x00010000
// <i> rwx RAM:  SRAM3_S from DFP:         BASE: 0x30040000  SIZE: 0x00080000
// <i> rwx RAM:  SRAM4_S from DFP:         BASE: 0x38000000  SIZE: 0x00004000
// <i> rwx RAM:  RAM-External from BSP:    BASE: 0x90000000  SIZE: 0x00800000
// <i> rx ROM:   Flash-External from BSP:  BASE: 0x70000000  SIZE: 0x04000000


#endif /* REGIONS_B_U585I_IOT02A_H */
