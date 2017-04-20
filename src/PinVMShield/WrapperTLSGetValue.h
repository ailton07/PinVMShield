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

int count = 0;

class WrapperTLSGetValue: public PinWrapperWinAPI
{
	private:
		/**
		 Wrapper of TlsGetValueA/TlsGetValueW Windows APIs. Spoofs the return if needed
				before returning to the caller
		 @param origFunc a pointer to the address of the original function (GetModuleHandleA/GetModuleHandleW)
		 @param lpBuffer a pointer to the buffer to receive the user's logon name
		 @param lpnSize on input, this variable specifies the size of the lpBuffer buffer, in TCHARs. 
						On output, the variable receives the number of TCHARs copied to the buffer, including the terminating null character
		 @param ctx a pointer to a CONTEXT Pin structure that stores the architectural state of the processor
		 @return a bool indicating whether the execution was successful
				For more information, check http://msdn.microsoft.com/en-us/library/windows/desktop/ms724432(v=vs.85).aspx
		 */
		static WINDOWS::LPVOID myTlsGetValue(AFUNPTR orig, 
										   WINDOWS::DWORD dwTlsIndex,
										   CONTEXT *ctx,
										   bool isUnicode)
		{
			WINDOWS::LPVOID retVal = 0;
			printMessage("\t-> [TLS_GV] Executando\n");
			PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
									CALLINGSTD_STDCALL, orig, NULL,
									PIN_PARG(WINDOWS::LPVOID), &retVal,
									PIN_PARG(WINDOWS::DWORD), dwTlsIndex,
									PIN_PARG_END()
									);

			// bool detectionVMs = checkDetection(ctx, "GetUserName", (char *)lpBuffer, isUnicode);
			// Forcing detection
			bool detectionVMs = (retVal !=0 ? true: false);

			if(detectionVMs)
			{
				count ++;
				printMessage("\t-> [TLS_GV] Asked for TLS values, spoofing return value\n");
				char textToPrint[4096];
				sprintf(textToPrint, "[Orginal] %d\n", reinterpret_cast<int>(retVal));
				printMessage(TEXT(textToPrint));

				if (count < 15) {
					retVal = (WINDOWS::LPVOID) 0;
				}
				
				sprintf(textToPrint, "[Modificada] %d\n\n", reinterpret_cast<int>(retVal));
				printMessage(TEXT(textToPrint));
				// WINDOWS::TCHAR* textToPrint2;
				//wchar_t* textToPrint2;

				//sprintf(textToPrint, "[Orginal] %s", lpBuffer);
				//printMessage(TEXT(textToPrint));

				//strcpy((char *)lpBuffer, "LadyBoysLover"); // XXX: Improve this, put some randomness...
				//sprintf(textToPrint, "[Modificada] %s", lpBuffer);
				//printMessage(textToPrint);
			}

			return retVal;
		}
	protected:
		PROTO GetPrototypeFunction(char *funcName)
		{
			return PROTO_Allocate( 
					PIN_PARG(WINDOWS::LPVOID), 
					CALLINGSTD_STDCALL, funcName,
					PIN_PARG(WINDOWS::DWORD),
					PIN_PARG_END()
					);
		}
		
		void ReplaceFunctionSignature(RTN rtn, PROTO proto, bool isUnicode)
		{
			printMessage("\t-> [TLS_GV] ReplaceFunctionSignature\n");
			RTN_ReplaceSignature(rtn, (AFUNPTR) WrapperTLSGetValue::myTlsGetValue,
					IARG_PROTOTYPE, proto,
					IARG_ORIG_FUNCPTR,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					IARG_CONTEXT,
					IARG_BOOL, isUnicode,
					IARG_END
					);
		}

		// No caso do TlsGetValue nao ha uma versao para ANSI e para UNICODE
		// Logo, nao ha uma versao A e W
		virtual RTN FindRTNByNameA(IMG img)
		{
			char *tmp = _strdup(this -> funcName);
			// RTN rtn = RTN_FindByName(img, strcat(tmp, "A"));
			RTN rtn = RTN_FindByName(img, tmp);
			free(tmp);
			return rtn;
	};

	public:
		WrapperTLSGetValue():PinWrapperWinAPI()
		{
			strcpy(this -> funcName, "TlsGetValue");
		}

		~WrapperTLSGetValue(){};
};