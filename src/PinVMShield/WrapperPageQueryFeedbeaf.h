/*
* @filename 		WrapperGetUserName.h
* @version			1.0, December 2013
* @author			R.J. Rodríguez (rjrodriguez@fi.upm.es), I. Rodríguez-Gastón (irodriguez@virtualminds.es)
* @description		Concrete class to wrap GetUserNameA/GetUserNameW Windows APIs
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
	Wrapper of TlsGetValue Windows APIs. Spoofs the return if needed
	before returning to the caller
	@param orig a pointer to the address of the original function (GetModuleHandleA/GetModuleHandleW)
	@param dwTlsIndex The TLS index that was allocated by the TlsAlloc function.
	@param ctx a pointer to a CONTEXT Pin structure that stores the architectural state of the processor
	@return a bool indicating whether the execution was successful
	For more information, check https://msdn.microsoft.com/pt-br/library/windows/desktop/ms686812(v=vs.85).aspx
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

			do {
				PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
					CALLINGSTD_STDCALL, orig, NULL,
					PIN_PARG(WINDOWS::SIZE_T), &retVal,
					PIN_PARG(WINDOWS::LPCVOID), baseAddress,
					PIN_PARG(WINDOWS::PMEMORY_BASIC_INFORMATION), lpBuffer,
					PIN_PARG(WINDOWS::SIZE_T), dwLength,
					PIN_PARG_END()
					);

				bool detectionVMs = (retVal !=0 ? true: false);
				isCodeCache = false;

				if(detectionVMs) {
					if (lpBuffer->AllocationProtect == 0x40) {
						//Só faz o 
						if (*baseAddress == 0xfeedbeaf) {
							isCodeCache = true;
						
							//Calculate the next region 
							WINDOWS::DWORD newAddress = WINDOWS::DWORD(baseAddress) + lpBuffer->RegionSize;

							//printf("base: %u region: %u new: %u\n", baseAddress, lpBuffer->RegionSize, newAddress);

							if (newAddress <= (WINDOWS::DWORD) baseAddress) {
								return retVal;
							}
							else {
								baseAddress = (unsigned long *) newAddress;
							}
						}
						else {
							return retVal;
						}
					}
					else {
						return retVal;
					}
				}

			} while(isCodeCache && retVal != 0);

			return retVal;
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