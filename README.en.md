# BYOVD-DriverKiller

This README (EN) may contain errors !

⚠️ **Disclaimer**: This project is strictly educational and demonstrative. It is not intended for malicious use.  
The goal is to learn reverse engineering methodology and the exploitation steps of a Windows driver.

---
Here I explain the approach I followed to solve the exercise proposed by d1rk (SaadAhla) [https://github.com/SaadAhla](https://github.com/SaadAhla/Killer-Exercice), consisting of performing reverse engineering and exploitation on a legitimate, signed driver, not present in blocklists (HVCI, LOLBIN...).  
A C program allowing to terminate any active process on the system via this Kernel-mode Driver is available, I detail its operation below.  

![POC-BYOD](https://github.com/user-attachments/assets/0d92f128-21fc-43ab-bc8b-6219fdc9e61e)

📃 **Usage**:  
```
DriverKiller.exe <process_name.exe> [-d]
```

Option -d: Removes the service and the Driver from the system after exploitation.  

Testsigning mode must be enabled on the target machine because the Driver’s certificate has expired.

---

## Part 1 - Reverse Engineering

The exercise provides a `.sys` file, named with its SHA-256 hash.  
The first step is to open this file with IDA.  
<sub>*IDA is available for free. You just need to go to the Hex-Rays website to generate a license and download the software.*</sub>

We start by listing the IAT (Import Address Table) of the Driver and searching for the API call we are interested in: `ZwTerminateProcess`.

<img width="1920" height="840" alt="screen1-git" src="https://github.com/user-attachments/assets/6f17b8c1-2588-4f41-b7e4-664ac093f3e4" />

Double-clicking on `ZwTerminateProcess` redirects us to the compiled code of this function. By selecting the entry and displaying the cross-references, we obtain the list of Driver functions that call it.

<img width="1920" height="869" alt="screen2-git" src="https://github.com/user-attachments/assets/73d8f1af-44f0-4993-80ac-9238af66d457" />

We see that the function `sub_12EF4`, at offset `1CE`, uses `ZwTerminateProcess`. After double-clicking, IDA displays its compiled code.

<img width="1920" height="874" alt="screen11-git" src="https://github.com/user-attachments/assets/ac7e53ef-94c8-4675-ba57-e62ff02b1114" />

The decompiled code reveals calls to `ZwOpenProcess` (which opens a handle to the target process) and to `ZwTerminateProcess` (which terminates the process via this handle).  

Looking at the documentation of `ZwOpenProcess` (https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwopenprocess), we see that the parameter `ClientID` corresponds to a pointer indicating the PID of the target process.  

On the line above, `ClientId.UniqueProcess` is initialized with variable `v22`. This is defined just above:  
```
v22 = (void *)(*(_QWORD *)i + 10);
```

To understand this assignment, we must identify variable `i` and the field `+10`.

<img width="1920" height="870" alt="screen3-git" src="https://github.com/user-attachments/assets/d5e89199-ae7a-4107-ab9a-54a977050352" />

Earlier in this function, we see a call to `ZwQuerySystemInformation` with parameter `SYSTEM_PROCESS_INFORMATION`. We also see that `i` is the iterator over the entries of this structure with variable `v6`.  

According to the documentation of `ZwQuerySystemInformation`: https://learn.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation, this function returns an array containing one entry per active process on the system.  

The structure `SYSTEM_PROCESS_INFORMATION` is described here: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation

```c
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;
```

Reminder: sizes of some types on Windows x64:

- ULONG = 4 bytes
- USHORT = 2 bytes
- HANDLE = 8 bytes
- PWSTR = 8 bytes
- KPRIORITY (typedef of LONG) = 4 bytes
- UNICODE_STRING = 16 bytes, since its structure is:
```c
typedef struct _UNICODE_STRING {
    USHORT Length;        -> 2      
    USHORT MaximumLength; -> + 2 = 4
    PWSTR  Buffer;        -> + 8 = 12 (12 is not a multiple of 8 so 4 bytes of padding are added before Buffer) = 16
} UNICODE_STRING;
```

Offset calculation of `UniqueProcessId`:
```
    ULONG NextEntryOffset;        -> 4
    ULONG NumberOfThreads;        -> + 4 = 8
    BYTE Reserved1[48];           -> + 48 = 56
    UNICODE_STRING ImageName;     -> + 16 = 72
    KPRIORITY BasePriority;       -> + 4 = 76 (76 is not a multiple of 8 so 4 bytes of padding are added) = 80
    HANDLE UniqueProcessId;       -> + 8 = 88
```
So <code>UniqueProcessId</code> is at offset 0x50 (80 in decimal).  

Looking at the assignment of variable <code>v22</code>, we see that <code>i</code> is cast as a pointer <code>QWORD</code> (8 bytes):  
<pre>
v22 = (void *)*((_QWORD *)i + 10);
</pre>

So <code>v22</code> corresponds to address of <code>i</code> + 10 * 8 = 80 bytes. This variable thus contains the PID retrieved from the SYSTEM_PROCESS_INFORMATION structure.  
To know which PID will be passed to <code>ZwTerminateProcess</code>, we need to analyze the condition surrounding this assignment.

<img width="1920" height="870" alt="screen4-git" src="https://github.com/user-attachments/assets/5510517c-ac61-48ce-94aa-60aab4f52f60" />

We can see that the process image name is first retrieved:

<pre>v9 = (wchar_t *)*((_QWORD *)i + 8);</pre>

Because <code>v9</code> = address of <code>i</code> + 8 × 8 = 64 bytes. This corresponds to the <code>Buffer</code> of the <code>ImageName</code> member, since this member is located at offset 56 + 2 (USHORT) + 2 (USHORT) + 4 (padding) = 64.

Given the manipulations and the loops below, we can hypothesize that a comparison is made between the process name passed as argument (<code>a2</code>) and the active processes on the system (<code>v9/String</code>):

<pre> sub_1C078(String, v9, (int)v13); v17 = strupr(a2); v18 = strupr(String); </pre>

Thus, the parameter <code>a2</code> is expected to contain the name of the process to be terminated via <code>ZwTerminateProcess</code>.
We can see that <code>a2</code> is a parameter of the function <code>sub_12EF4</code>. To go further, we need to examine the references to this function (I renamed it <code>ZwTerminateProcessCaller</code> for better readability).

<img width="1920" height="872" alt="screen5-git" src="https://github.com/user-attachments/assets/eada954b-d339-4a46-8362-a38ffde8f5d7" />

We can see that <code>ZwTerminateProcessCaller</code> is called by the function <code>sub_13624</code> at offset <code>61A</code>.

<img width="1920" height="871" alt="screen6-git" src="https://github.com/user-attachments/assets/f514c732-538d-4364-81be-15ce150bcd1c" />

Before analyzing this decompiled code, I check the references of function <code>sub_13624</code> (renamed <code>ZwTerminateProcessCallerCaller</code>) to make sure this code is indeed used after an API call to <code>DeviceIoControl</code> from UserMode.

<img width="1920" height="872" alt="screen§-git" src="https://github.com/user-attachments/assets/8cce90f7-a0cb-46fb-bfcc-5ef39f1afc2a" />

We can see that <code>ZwTerminateProcessCallerCaller</code> is called by the function <code>sub_14130</code> (renamed <code>ZwTerminateProcessCallerCallerCaller</code> ... fortunately for us, this is the last one before the entry point 😅).

<img width="1920" height="875" alt="screen7-git" src="https://github.com/user-attachments/assets/4806434d-d3d5-474d-ad6a-60480806d946" />

We can see that <code>ZwTerminateProcessCallerCallerCaller</code> is called by the function <code>sub_1A4A8</code> at offset <code>306</code>.

<img width="1920" height="875" alt="screen8-git" src="https://github.com/user-attachments/assets/f463ee14-b290-4d16-ac18-9902b175a3fb" />

We find the assignment of the function <code>ZwTerminateProcessCallerCallerCaller</code>:

<pre>memset64(DriverObject->MajorFunction, (unsigned __int64)ZwTerminateProcessCallerCallerCaller, 0x1Cu);</pre>

Which means this function is assigned to all entries of the MajorFunction table (0x1B = 27, and there are 28 major IRPs).

<img width="1920" height="869" alt="screen9-git" src="https://github.com/user-attachments/assets/bfd21b4c-a0c8-43f6-8305-73d52e0859c8" />

Before returning to function <code>sub_13624</code> (aka <code>ZwTerminateProcessCallerCaller</code>), we retrieve the Symbolic Name and Device Name (identical here): <code>Viragtlt</code>.

<img width="1920" height="870" alt="screen12-git" src="https://github.com/user-attachments/assets/98b7ff4e-85d6-4592-96fd-05c4be78e3fb" />

Going back to <code>ZwTerminateProcessCallerCaller</code>, we notice that its second parameter (thus <code>a2</code>) corresponds to <code>MasterIrp->AssociatedIrp.SystemBuffer</code>.<br>

<img width="1920" height="870" alt="screen13-git" src="https://github.com/user-attachments/assets/f3c29457-7677-476a-be51-5936910a7b81" />

Just above the call to <code>ZwTerminateProcessCaller</code> we find the IOCTL code: <code>-2106392528</code> (in hexadecimal: <code>0x82730030</code>).<br>

With this information, we can deduce that to exploit this Driver, one must send a <code>DeviceIoControl</code> API call to the Driver with the name of the process to be terminated in the SystemBuffer.

---

🔷 **Information recovered thanks to reverse engineering**:

- IOCTLCode: `0x82730030`
- Device Name: `Viragtlt`
- Symbolic Name: `Viragtlt`
- SystemBuffer must contain the target process name

---

## Part 2 - Exploitation

To exploit this Driver (if installed and active on the target machine), it is necessary to open a handle to it, then make a `DeviceIoControl` API call with a Buffer containing the name of the process to terminate.  

For this exercise, I developed a C project that:
- Checks if the Driver is present and active on the system (with a specific service name):
  - If yes, the program exploits the Driver with a `DeviceIoControl` API call.
  - If no, the program extracts the driver from its resources, deploys it on the user’s desktop, creates an active service, then exploits the Driver with a `DeviceIoControl` API call. (Requires admin rights since a service is created.)
- If the Driver is present on the system but the service is not started, the program attempts to start the service then exploits it with a `DeviceIoControl` API call.

I also added a `-d` option that allows to remove the service and the Driver from the system after exploitation.

Here is the behavior of the C program in its full execution cycle:

![git](https://github.com/user-attachments/assets/3cb6a57e-45a1-4607-b7f1-fe1dcb5ddb27)

---

## AV/EDR Evasion

In this case, DriverKiller.exe is not detected by Microsoft Defender, neither statically nor dynamically.  
Evasion does not really make sense here because the exploited Driver has an expired certificate, making its use in real-world scenarios unlikely.  
But for better stealth, one could have implemented:

- Hiding some API calls in the IAT via custom implementations of GetProcAddress and GetModuleHandle
- A closer approach to the Kernel for executing API calls (Direct/Indirect Syscalls)
- Anti-VM / Anti-Debug techniques

---

⚠️ This project was carried out in a learning context. It may contain inaccuracies or errors. Any suggestion, correction, or discussion is welcome! 😃  
Thanks to d1rk (SaadAhla): https://github.com/SaadAhla
