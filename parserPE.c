#include <Windows.h>
#include <stdio.h>


PIMAGE_DOS_HEADER		 pImageDosHeader		= NULL;
PIMAGE_NT_HEADERS		 pImageNTHeader			= NULL;
PIMAGE_FILE_HEADER		 pImageFileHeader		= NULL;
PIMAGE_OPTIONAL_HEADER	 pImageOptionalHeader	= NULL;
PIMAGE_SECTION_HEADER	 pImageSectionHeader	= NULL;
PIMAGE_DATA_DIRECTORY    pImageDataDirectory	= NULL;
PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = NULL;
PIMAGE_THUNK_DATA		 pImageThunkData		= NULL;
PIMAGE_IMPORT_BY_NAME	 pImageImportByName		= NULL;
PIMAGE_EXPORT_DIRECTORY	 pImageExportDirectory	= NULL;

DWORD pImageSectionHeaderVirtualAddressForImport	= 0;
DWORD pImageSectionHeaderRawDataForImport			= 0;
DWORD pImageSectionHeaderVirtualAddressForExport	= 0;
DWORD pImageSectionHeaderRawDataForExport			= 0;

/*
* Open File
*/
HANDLE getFile(LPCTSTR fileName)
{
	HANDLE handleFile;
	handleFile = CreateFile(
			fileName,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_READONLY,
			NULL
		);
	return handleFile;
}

/*
* Get Raw Data Address Import
*/
DWORD getRawDataAddressImport(DWORD VirtualAddress)
{
	DWORD res;
	res = VirtualAddress - pImageSectionHeaderVirtualAddressForImport;
	res = res + pImageSectionHeaderRawDataForImport;
	res = res + (DWORD)pImageDosHeader;
	return res;
}

/*
* Get Raw Data Address Export
*/
DWORD getRawDataAddressExport(DWORD VirtualAddress)
{
	DWORD res;
	res = VirtualAddress - pImageSectionHeaderVirtualAddressForExport;
	res = res + pImageSectionHeaderRawDataForExport;
	res = res + (DWORD)pImageDosHeader;
	return res;
}

/*
* Get Sections
*/
void getSections()
{
	unsigned int i = 0;
	while (i < pImageFileHeader->NumberOfSections)
	{
		i++;
		printf("SectionHeader %d : %s - %x - %x\n", i, pImageSectionHeader->Name, pImageSectionHeader->VirtualAddress, pImageSectionHeader->VirtualAddress + pImageSectionHeader->SizeOfRawData);
		printf("Section RawData : %x\n", pImageSectionHeader->PointerToRawData);
		if ((pImageSectionHeader->VirtualAddress < (pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]).VirtualAddress) && (pImageSectionHeader->VirtualAddress + pImageSectionHeader->SizeOfRawData > (pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]).VirtualAddress))
		{
			pImageSectionHeaderVirtualAddressForImport = pImageSectionHeader->VirtualAddress;
			pImageSectionHeaderRawDataForImport = pImageSectionHeader->PointerToRawData;
			pImageImportDescriptor =
				(PIMAGE_IMPORT_DESCRIPTOR) getRawDataAddressImport((pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]).VirtualAddress);
		}
		if ((pImageSectionHeader->VirtualAddress < (pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress) && (pImageSectionHeader->VirtualAddress + pImageSectionHeader->SizeOfRawData > (pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress))
		{
			pImageSectionHeaderVirtualAddressForExport = pImageSectionHeader->VirtualAddress;
			pImageSectionHeaderRawDataForExport = pImageSectionHeader->PointerToRawData;
			pImageExportDirectory =
				(PIMAGE_EXPORT_DIRECTORY) getRawDataAddressExport((pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress);
		}
		pImageSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pImageSectionHeader + sizeof(IMAGE_SECTION_HEADER));
	}
}

/*
* Get Import
*/
void getImport()
{
	printf("IMPORT:\n");
	while(pImageImportDescriptor->Characteristics != (DWORD)NULL)
	{
		printf("%s\n*", getRawDataAddressImport(pImageImportDescriptor->Name));
		pImageThunkData = (PIMAGE_THUNK_DATA) getRawDataAddressImport(pImageImportDescriptor->OriginalFirstThunk);
		while(pImageThunkData->u1.ForwarderString != (DWORD)NULL)
		{ 
			if(IMAGE_SNAP_BY_ORDINAL(pImageThunkData->u1.Ordinal))
			{
				printf("%x ", IMAGE_ORDINAL(getRawDataAddressImport(pImageThunkData->u1.Ordinal)));
			}
			else
			{
				pImageImportByName = (PIMAGE_IMPORT_BY_NAME)getRawDataAddressImport(pImageThunkData->u1.AddressOfData);
				printf("%s ", pImageImportByName->Name);
			}	
				
			pImageThunkData = (PIMAGE_THUNK_DATA)((DWORD)pImageThunkData + sizeof(IMAGE_THUNK_DATA));
		}
		pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		printf("\n-----\n");
	}
}

/*
* MAIN
*/
int main (int argc, char* argv[])
{
	HANDLE handleFile;
	DWORD sizeBufferOut;
	PVOID outBuffer;

	// Buffer
	if((outBuffer = (LPVOID)malloc(1000000000)) == 0)
	{
		printf("Buffer = 0 FAIL %x", GetLastError());
		getchar();
		return (EXIT_FAILURE);
	}
	printf("Fichier : %s\n", argv[1]);

	// Open file
	if((handleFile = getFile(argv[1])) == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile FAIL %x", GetLastError());
		getchar();
		return (EXIT_FAILURE);
	}

	// Read file
	if(ReadFile(
			handleFile,
			outBuffer,
			1000000000,
			&sizeBufferOut,
			NULL
		)
		== FALSE
	)
	{
		printf("ReadFile FAIL %x", GetLastError());
		getchar();
		return (EXIT_FAILURE);
	}

	// Get Dos Header Address
	pImageDosHeader =
		(PIMAGE_DOS_HEADER)outBuffer; // (PIMAGE_DOS_HEADER)handleFile;

	// Get NT Header Address
	pImageNTHeader =
		(PIMAGE_NT_HEADERS)((char*)pImageDosHeader + pImageDosHeader->e_lfanew);
	printf("pImageDosHeader : %x\npImageNTHeader  : %x\n", pImageDosHeader, pImageNTHeader);

	// Image File Header
	pImageFileHeader =
		&(pImageNTHeader->FileHeader);

	// Image Optional Header
	pImageOptionalHeader =
		&(pImageNTHeader->OptionalHeader);

	// Image Section Header
	pImageSectionHeader =
		(PIMAGE_SECTION_HEADER)((char*)pImageNTHeader + sizeof(IMAGE_NT_HEADERS));

	printf("pImageSectionHeader : %x\n", pImageSectionHeader);
	printf("Image Base : %x\nEntryPoint : %x\nNombre de section : %d\n---\n",
		pImageOptionalHeader->ImageBase,
		pImageOptionalHeader->AddressOfEntryPoint,
		pImageFileHeader->NumberOfSections
	);

    // Sections
	getSections();

    // Import
	getImport();
	
	getchar();

	return (EXIT_SUCCESS);
}
