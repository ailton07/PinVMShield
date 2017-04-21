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
		 Wrapper of TlsGetValue Windows APIs. Spoofs the return if needed
				before returning to the caller
		 @param orig a pointer to the address of the original function (GetModuleHandleA/GetModuleHandleW)
		 @param dwTlsIndex The TLS index that was allocated by the TlsAlloc function.
		 @param ctx a pointer to a CONTEXT Pin structure that stores the architectural state of the processor
		 @return a bool indicating whether the execution was successful
				For more information, check https://msdn.microsoft.com/pt-br/library/windows/desktop/ms686812(v=vs.85).aspx
		 */
		static WINDOWS::LPVOID myTlsGetValue(AFUNPTR orig, 
										   WINDOWS::DWORD dwTlsIndex,
										   CONTEXT *ctx,
										   bool isUnicode)
		{
			WINDOWS::LPVOID retVal = 0;
			// TlsGetValue e muito executado, logo os prints desnecassarios para o rastreio do 
			// funcionamento serao omitidos
			// printMessage("\t-> [TLS_GV] Executando\n");
			PIN_CallApplicationFunction(ctx, PIN_ThreadId(),
									CALLINGSTD_STDCALL, orig, NULL,
									PIN_PARG(WINDOWS::LPVOID), &retVal,
									PIN_PARG(WINDOWS::DWORD), dwTlsIndex,
									PIN_PARG_END()
									);

			// bool detectionVMs = checkDetection(ctx, "GetUserName", (char *)lpBuffer, isUnicode);
			bool detectionVMs;
			
			// Checa se houve um valor de retorno
			// detectionVMs = true;
			detectionVMs = (retVal !=0 ? true: false);

			if(detectionVMs)
			{
				char textToPrint[4096];	
				// Pin utiliza por padrao os 5 primeiros slots TLS
				// Os valores previamente existentes sao deslocados em 5
				// O que estava no slot 1, vai para o slot 6
				// Logo, so precisamos spoofar os 5 primeiros slots
				 if (dwTlsIndex < 6) 
				 {
					 printMessage("\t-> [TLS_GV] Asked for TLS values, spoofing return value\n");
					 sprintf(textToPrint, "[Orginal] %d\n", reinterpret_cast<int>(retVal));
					 printMessage(TEXT(textToPrint));
					
					 retVal = (WINDOWS::LPVOID) 0;
					
					sprintf(textToPrint, "[Modificada] %d\n\n", reinterpret_cast<int>(retVal));
					printMessage(TEXT(textToPrint));
				}
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