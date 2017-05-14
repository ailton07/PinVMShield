/*
 * @filename 		PinVMShield.cpp
 * @version			1.0, November 2013
 * @author			R.J. Rodríguez (rjrodriguez@fi.upm.es), I. Rodríguez-Gastón (irodriguez@virtualminds.es)
 * @description		Implements a pintool to avoid sandbox and virtual machine detection. 
 *		It is intended to be integrated with Cuckoo Sandbox for performing malware analysis tasks.
 *      Check for its last version at BitBucket: https://bitbucket.org/rjrodriguez/pinvmshield
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

#include "pin.H"
#include <stdio.h>
#include <vector>

#include "PinWrapperWinAPI.h"

// APIs
#include "WrapperGetUserName.h"
#include "WrapperGetUserNameEx.h"
#include "WrapperRegQueryValue.h"
#include "WrapperRegQueryValueEx.h"
#include "WrapperRegOpenKey.h"
#include "WrapperRegOpenKeyEx.h"
#include "WrapperGetModuleHandle.h"
#include "WrapperGetModuleHandleEx.h"
#include "WrapperGetFileAttributes.h"
#include "WrapperProcess32FirstAndNext.h"
#include "WrapperFindWindow.h"
#include "WrapperFindWindowEx.h"
#include "WrapperCreateFile.h"
#include "WrapperCreateNamedPipe.h"
#include "WrapperGetCursorPos.h"
#include "WrapperCallNamedPipe.h"
#include "WrapperTLSGetValue.h"

#include "WrapperCodeCache.h"

#include <string.h>

#define codeCacheBlockSize 0x40000

ADDRINT _baseM = 0;
ADDRINT _endM = 0;

std::vector<ADDRINT> addrintVector;

VOID PrintImageInformations (IMG img);

/**
 Called by Pin, fakes the APIs. Check above code
 @param img an IMG represents all the data structures corresponding to a binary (executable or library)
 @param v a pointer
 */
VOID Image(IMG img, VOID *v)
{
		vector<PinWrapperWinAPI*>  vWinAPIs;

		// Fill vector properly...
		vWinAPIs.push_back(new WrapperTLSGetValue()); // API TLSGetValue

		vWinAPIs.push_back(new WrapperGetUserName()); // API GetUserNameA/W
		vWinAPIs.push_back(new WrapperGetUserNameEx()); // API GetUserNameExA/W
		vWinAPIs.push_back(new WrapperRegQueryValue()); // API RegQueryValueA/W
		vWinAPIs.push_back(new WrapperRegQueryValueEx()); // API RegQueryValueExA/W
		vWinAPIs.push_back(new WrapperRegOpenKey()); // API RegOpenKeyA/W
		vWinAPIs.push_back(new WrapperRegOpenKeyEx()); // API RegOpenKeyExA/W
		vWinAPIs.push_back(new WrapperGetModuleHandle()); // API GetModuleHandleA/W
		vWinAPIs.push_back(new WrapperGetModuleHandleEx()); // API GetModuleHandleExA/W
		vWinAPIs.push_back(new WrapperGetFileAttributes()); // API GetFileAttributesA/W
		//XXX This is not working, needs to be revised...
		//vWinAPIs.push_back(new WrapperProcess32FirstAndNext()); // API Process32First / Process32Next
		vWinAPIs.push_back(new WrapperFindWindow()); // API FindWindowA/W
		vWinAPIs.push_back(new WrapperFindWindowEx()); // API FindWindowExA/W
		vWinAPIs.push_back(new WrapperCreateFile()); // API CreateFileA/W
		vWinAPIs.push_back(new WrapperCreateNamedPipe()); // API CreateNamedPipeA/W
		vWinAPIs.push_back(new WrapperGetCursorPos()); // API GetCursorPos
		vWinAPIs.push_back(new WrapperCallNamedPipe()); // API CallNamedPipe

		// And iterates over the components...
		for(vector<PinWrapperWinAPI*>::iterator it = vWinAPIs.begin(); it != vWinAPIs.end(); it++)
		{
			(*it) -> ReplaceWinAPI(img);
		}
}

/**
 Print informations about image on load
 Load base and end address of .exe image
 @param img an IMG represents all the data structures corresponding to a binary (executable or library)
 */
VOID PrintImageInformations (IMG img) 
{
	// https://www.linkedin.com/pulse/visualizing-program-execution-binary-ninja-dynamic-britton-manahan
	char str[4096];
	char textToPrint[4096];
	strcpy (str, IMG_Name(img).c_str());
	printMessage(str);
	// Checa se trata-se do executavel
	if ( strstr(str, ".exe") != NULL )
	{
		printMessage(str);
		
		_baseM = IMG_LowAddress(img);
		_endM = IMG_HighAddress(img);

		LOG(StringFromAddrint(_baseM));
		LOG(StringFromAddrint(_endM));
	}
}

/**
 Last function of pintool that will be executed
 */
VOID Fini(INT32 code, VOID *v)
{
	fprintf(stdout, "Exiting...\n");
	if(logFile != NULL)
		fclose(logFile);
}

// https://github.com/jingpu/pintools/blob/master/source/tools/CacheClient/insertDelete.cpp
/**
 Preenche uma lista com as informacoes sobre os CodeCaches
 This method obtain information about codecache address.
 */
VOID WatchTraces(TRACE trace, VOID *v)
{
    char textToPrint[4096];
	ADDRINT orig_pc = TRACE_Address(trace);
	ADDRINT codeCacheAddress = TRACE_CodeCacheAddress(trace);

	for(int i = 0 ; i < addrintVector.size(); i++)
    {
		if ((addrintVector[i] == codeCacheAddress) ||
			(codeCacheAddress > addrintVector[i]) && 
			(codeCacheAddress < addrintVector[i] + codeCacheBlockSize))
			return;
	 }

	{

		sprintf(textToPrint, "\n[TRACE_Address] 0x%x ", orig_pc);
		printMessage(TEXT(textToPrint));

		sprintf(textToPrint, "\t[TRACE_CodeCacheAddress] 0x%x ", codeCacheAddress);
		printMessage(TEXT(textToPrint));

		sprintf(textToPrint, "\t[TRACE_Size] 0x%x ", TRACE_Size(trace));
		printMessage(TEXT(textToPrint));

		sprintf(textToPrint, "\t[TRACE_CodeCacheSize] 0x%x \n", TRACE_CodeCacheSize(trace));
		printMessage(TEXT(textToPrint));

		addrintVector.push_back(codeCacheAddress);
	}
}

// Versao nao estruturada
// Is called for every instruction and instruments reads and writes
ADDRINT GetMemAddress( VOID * ip, ADDRINT ea)
	{
		long _addr = (long) (ea);

		for(int i = 0 ; i < addrintVector.size(); i++)
		{
			if ((addrintVector[i] == _addr) ||
				(_addr > addrintVector[i]) && 
				(_addr < addrintVector[i] + codeCacheBlockSize))
			{
				_addr = (ea) + 0x40000;
				return static_cast<ADDRINT>(_addr);
			}
		}
		return ea;
	}

	static REG GetScratchReg(UINT32 index)
	{
		static std::vector<REG> regs;

		while (index >= regs.size())
		{
			REG reg = PIN_ClaimToolRegister();
			if (reg == REG_INVALID())
			{
				PIN_ExitProcess(1);
				/* does not return */
			}
			regs.push_back(reg);
		}

		return regs[index];
	}

VOID Instruction(INS ins, VOID *v)
{
	// Instruments memory accesses using a predicated call, i.e.
	// the instrumentation is called iff the instruction will actually be executed.
	//
	// On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
	// prefixed instructions appear as predicated instructions in Pin.
	UINT32 memOperands = INS_MemoryOperandCount(ins);

	// Iterate over each memory operand of the instruction.
	for (UINT32 memOp = 0; memOp < memOperands; memOp++)
	{
		if (INS_MemoryOperandIsRead(ins, memOp))
		{
			/*INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
			IARG_INST_PTR,
			IARG_MEMORYOP_EA, memOp,
			IARG_END);*/
			// https://svn.mcs.anl.gov/repos/performance/Gwalp/gwalpsite/pin/source/tools/SignalTests/null-rewrite-tool.cpp
			REG scratchReg = GetScratchReg(memOp);

			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(GetMemAddress),
				IARG_INST_PTR,
				IARG_MEMORYOP_EA, memOp,
				IARG_RETURN_REGS, scratchReg,
				IARG_END);

			INS_RewriteMemoryOperand(ins, memOp, scratchReg);
		}
	}
}

// TODO: Corrigir versao estruturada do CodeCacheWrapper
// ERRO: E: Unexpected memory deallocation request of aligned memory 01800400
// Versao estruturada
//VOID Instruction(INS ins, VOID *v)
//{
//	WrapperCodeCache wcc = WrapperCodeCache(addrintVector, codeCacheBlockSize);
//	wcc.Instruction(ins, v);
//}

/**
 Main procedure of pintool. Not very interested to comment if you are related to Pintools development
 */
int main(int argc, char *argv[])
{
	// Initialize pin & symbol manager
    PIN_InitSymbols();
    PIN_Init(argc,argv);

	// Register Image to be called to instrument functions.
    IMG_AddInstrumentFunction(Image, 0);

	CODECACHE_AddTraceInsertedFunction(WatchTraces, 0);

	INS_AddInstrumentFunction(Instruction , 0);

	printMessage("\t-> PIN_StartProgram();\n");

    PIN_StartProgram(); // Never returns
    
    return 0;
}