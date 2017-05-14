#pragma once
#include "pin.H"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


class WrapperCodeCache
{
private:
	static long _codeCacheBlockSize;
	static std::vector<ADDRINT> _addrintVector;

	public:

		WrapperCodeCache(std::vector<ADDRINT> addrintVector, long ccodeCacheBlockSize)
		{
			_addrintVector = addrintVector;
			_codeCacheBlockSize = ccodeCacheBlockSize;
		}

		~WrapperCodeCache(){};

	// Is called for every instruction and instruments reads and writes
	static ADDRINT GetMemAddress( VOID * ip, ADDRINT ea)
	{
		long _addr = (long) (ea);

		for(int i = 0 ; i < _addrintVector.size(); i++)
		{
			if ((_addrintVector[i] == _addr) ||
				(_addr > _addrintVector[i]) && 
				(_addr < _addrintVector[i] + _codeCacheBlockSize))
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
		// std::vector<REG> regs;

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

	static VOID WrapperCodeCache::Instruction(INS ins, VOID *v)
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
				// https://svn.mcs.anl.gov/repos/performance/Gwalp/gwalpsite/pin/source/tools/SignalTests/null-rewrite-tool.cpp
				REG scratchReg = GetScratchReg(memOp);

				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(WrapperCodeCache::GetMemAddress),
					IARG_INST_PTR,
					IARG_MEMORYOP_EA, memOp,
					IARG_RETURN_REGS, scratchReg,
					IARG_END);

				INS_RewriteMemoryOperand(ins, memOp, scratchReg);
			}
		}
	}

};