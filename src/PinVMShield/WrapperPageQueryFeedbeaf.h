/*
* @filename 		WrapperPageQueryFeedbeaf.h
* @version			1.1, Oct 2018
* @author			A. da Silva
* @description		
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "PinWrapperWinAPI.h"


class WrapperPageQueryFeedbeaf: public PinWrapperWinAPI {
private:
	/**
	Wrapper of VirtualQuery Windows APIs. Spoofs the return if needed
	before returning to the caller
	@param lpAddress [in, optional] a pointer to the base address of the region of pages to be queried.
	@param lpBuffer [out] a pointer to a MEMORY_BASIC_INFORMATION structure in which information about the specified page range is returned.
	@param dwLength [in] the size of the buffer pointed to by the lpBuffer parameter, in bytes.
	@return the return value is the actual number of bytes returned in the information buffer.
	For more information, check https://msdn.microsoft.com/en-us/library/windows/desktop/aa366902(v=vs.85).aspx
	*/
	static WINDOWS::SIZE_T myPageQuery(AFUNPTR orig, 
		WINDOWS::LPCVOID lpAddress,
		WINDOWS::PMEMORY_BASIC_INFORMATION lpBuffer,
		WINDOWS::SIZE_T dwLength,
		CONTEXT *ctx,
		bool isUnicode) {
			WINDOWS::SIZE_T retVal = 0;
			bool isCodeCache = false;
			unsigned long* baseAddress = (unsigned long *) lpAddress;

			PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
				CALLINGSTD_STDCALL, orig, NULL,
				PIN_PARG(WINDOWS::SIZE_T), &retVal,
				PIN_PARG(WINDOWS::LPCVOID), baseAddress,
				PIN_PARG(WINDOWS::PMEMORY_BASIC_INFORMATION), lpBuffer,
				PIN_PARG(WINDOWS::SIZE_T), dwLength,
				PIN_PARG_END()
				);

			bool detectionVMs = (retVal !=0 ? true: false);
			if(detectionVMs) {
#ifdef debug
				if ((lpBuffer->AllocationProtect == 0x40) && (unsigned long)(*lpBuffer).BaseAddress < 0x70000000) {
					char textToPrint[4096];	
					//sprintf(textToPrint, "[Orginal] 0x%x\n", reinterpret_cast<unsigned long*>(baseAddress));
					sprintf(textToPrint, "[ANTES] 0x%x\n", (*lpBuffer).BaseAddress);
					printMessage(TEXT(textToPrint));

					sprintf(textToPrint, "[Orginal] 0x%x\n", getPageContent(reinterpret_cast<unsigned long*>((*lpBuffer).BaseAddress)));
					printMessage(TEXT(textToPrint));

					sprintf(textToPrint, "[Orginal] e igual a 0xfeedbeaf ? %d\n", getPageContent(reinterpret_cast<unsigned long*>((*lpBuffer).BaseAddress)) == 0xfeedbeaf ? true: false);
					printMessage(TEXT(textToPrint));

					sprintf(textToPrint, "[DEPOIS]\n");
					printMessage(TEXT(textToPrint));
					//return retVal;
					//return 0;
				}
#endif
				// 0x40 = PAGE_EXECUTE_READWRITE // https://docs.microsoft.com/en-us/windows/desktop/memory/memory-protection-constants
				// baseAddress >  0x70000000 is OS reserved
				if ((lpBuffer->AllocationProtect == 0x40) && ((unsigned long) baseAddress <  0x70000000)) {
					if (*baseAddress == 0xfeedbeaf) {
						return 0;
					}
				}
			}
			return retVal;
	}

	static unsigned long getPageContent(unsigned long *p) {
		__try {
			//printf("%x\n", *p);
			return *p;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			char textToPrint[4096];	
			WINDOWS::DWORD dw = WINDOWS::GetLastError(); 
			sprintf(textToPrint, "[GetLastError] %d\n", dw);
			printMessage(TEXT(textToPrint));
			return NULL;
		}
	}

protected:
	PROTO GetPrototypeFunction(char *funcName) {
		return PROTO_Allocate( 
			PIN_PARG(WINDOWS::SIZE_T), 
			CALLINGSTD_STDCALL, 
			funcName,
			PIN_PARG(WINDOWS::LPCVOID),
			PIN_PARG(WINDOWS::PMEMORY_BASIC_INFORMATION),
			PIN_PARG(WINDOWS::SIZE_T),
			PIN_PARG_END()
			);
	}

	void ReplaceFunctionSignature(RTN rtn, PROTO proto, bool isUnicode) {
		printMessage("\t-> [TLS_GV] ReplaceFunctionSignature\n");

		RTN_ReplaceSignature(rtn, (AFUNPTR) WrapperPageQueryFeedbeaf::myPageQuery,
			IARG_PROTOTYPE, proto,
			IARG_ORIG_FUNCPTR,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_CONTEXT,
			IARG_BOOL, isUnicode,
			IARG_END
			);
	}


	virtual RTN FindRTNByNameA(IMG img) {
		char *tmp = _strdup(this -> funcName);
		// RTN rtn = RTN_FindByName(img, strcat(tmp, "A"));
		RTN rtn = RTN_FindByName(img, tmp);
		free(tmp);
		return rtn;
	};

public:
	WrapperPageQueryFeedbeaf():PinWrapperWinAPI() {
		strcpy(this -> funcName, "VirtualQuery");
	}
	~WrapperPageQueryFeedbeaf(){};
};