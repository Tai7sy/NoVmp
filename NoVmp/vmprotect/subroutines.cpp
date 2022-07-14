// Copyright (C) 2020 Can Boluk
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
#include "subroutines.hpp"

namespace vmp
{
	// Reduces the given virtualized instruction handler to the base 
	// (AKA Deobfuscation + I/O based Register tracing)
	//
	void reduce_chunk( vm_state* vstate, instruction_stream& is, const std::vector<std::pair<rkey_block*, rkey_value>>& parameters, bool has_next )
	{
		for ( auto& parameter_pair : parameters )
		{
			rkey_block* block = parameter_pair.first;

			int i_0 = 0;
			for ( auto& ins : is.stream )
			{
				if ( ins.second.address == block->block_start.second )
				{
					i_0 = ins.first;
					break;
				}
			}

			int i_1 = 0;
			for ( auto& ins : is.stream )
			{
				if ( ins.second.address == block->block_end.second )
				{
					i_1 = ins.first;
					break;
				}
			}

			// Strip all of the decryption block
			is.stream.erase( std::remove_if( is.stream.begin(), is.stream.end(), [ & ] ( auto& p )
			{
				return i_0 <= p.first && p.first <= i_1;
			} ), is.stream.end() );

			// Append fake instruction
			// > MOV r64, imm64
			vtil_instruction ins;
			ins.address = -1;
			ins.id = X86_INS_INVALID;
			ins.mnemonic = "loadc";
#if _M_X64 || __x86_64__
			ins.operand_string = vtil::amd64::name( block->output_register );
			ins.operand_string += ", " + std::to_string( parameter_pair.second.u64 );
#else
			ins.operand_string = vtil::x86::name( block->output_register );
			ins.operand_string += ", " + std::to_string( parameter_pair.second.u32 );
#endif
			
			ins.regs_write.insert( block->output_register );

			ins.operands.resize( 2 );
			ins.eflags = 0;
			ins.operands[ 0 ].type = X86_OP_REG;
			ins.operands[ 0 ].reg = block->output_register;
			ins.operands[ 0 ].access = CS_AC_WRITE;
			ins.operands[ 0 ].size = block->output_size;

			ins.operands[ 1 ].type = X86_OP_IMM;
#if _M_X64 || __x86_64__
			ins.operands[ 1 ].imm = parameter_pair.second.i64;
#else
			ins.operands[ 1 ].imm = parameter_pair.second.i32;
#endif
			ins.operands[ 1 ].size = block->output_size;
			is.stream.push_back( { i_1, ins } );

			// Normalize the stream
			is.normalize();
		};

		// Trace all changes to RSP and VSP
		//
		std::map<x86_reg, bool> traced = {};
		traced[ X86::REG::SP ] = true;
		traced[ vstate->reg_vsp ] = true;

		// If JA is present, always take the branch
		//
		int ja_i = is.next( X86_INS_JA, { X86_OP_IMM } );
		if ( ja_i != -1 )
			is.stream.resize( ja_i );

		// Trace the instruction from the end of the control flow
		//
		instruction_stream is_reduced = {};
		for ( auto i = (int32_t)is.stream.size() - 1; i >= 0; i-- )
		{
			auto& ins = is[ i ];

			// Skip if we hit the xor block preceding the decryption rkb
			//
			if ( has_next &&
				 ins.id > parameters.back().first->block_start.first &&
				 ins.is( X86_INS_XOR, { X86_OP_MEM, X86_OP_REG } ) &&
				 ins.operands[ 0 ].mem.base == X86::REG::SP &&
				 vtil_registers.extend( ins.operands[ 1 ].reg ) == vtil_registers.extend( parameters.back().first->output_register ) )
			{
				// vtil::logger::warning( "Why there is still a key block ??? " );
				continue;
			}

			// Blacklist certain instructions as they
			// mess up with our vtil_registers.extend logic or FLAGS
			//
			if ( ins.id == X86_INS_CQO ||
				 ins.id == X86_INS_CWD ||
				 ins.id == X86_INS_CBW ||
				 ins.id == X86_INS_CWDE ||
				 ins.id == X86_INS_CDQ ||
				 ins.id == X86_INS_CDQE ||
				 ins.id == X86_INS_LAHF ||
				 ins.id == X86_INS_TEST ||
				 ins.id == X86_INS_CMP )
			{
				continue;
			}

			// Self references are always logged
			//
#if _M_X64 || __x86_64__
			// lea	r9, [rip - 7] 
			if ( ins.is( X86_INS_LEA, { X86_OP_REG, X86_OP_MEM } ) &&
				 ins.operands[ 1 ].mem.disp == -7 &&
				 ins.operands[ 1 ].mem.scale == 1 &&
				 ins.operands[ 1 ].mem.base == X86_REG_RIP &&
				 ins.operands[ 1 ].mem.index == X86_REG_INVALID )
#else
			// lea	edi, [0x4963c1]
			if ( ins.is(X86_INS_LEA, { X86_OP_REG, X86_OP_MEM }) && 
				 ins.operands[ 1 ].mem.disp == vstate->img->get_mapped_image_base() + ins.address &&
				 ins.operands[ 1 ].mem.scale == 1 &&
				 ins.operands[ 1 ].mem.base == X86_REG_INVALID &&
				 ins.operands[ 1 ].mem.index == X86_REG_INVALID )
#endif
			{
				// Do not trace till the ADD of the jump destination calculation though
				//
				is_reduced.stream.push_back( is.stream[ i ] );
				continue;
			}

			// PUSHFQ is always logged
			//
			if ( ins.is( X86::INS::PUSHF, {} ) )
			{
				// Nothing to trace
				//
				is_reduced.stream.push_back( is.stream[ i ] );
				continue;
			}

			// Check whether the register is read / written to by this instruction
			// (Non-implicit operand-invoked R/W only)
			//
			std::map<x86_reg, bool> reads;
			std::map<x86_reg, bool> writes;
			uint64_t mem_read = false;
			uint64_t mem_write = false;
			uint64_t eflags_write = ins.eflags;

			for ( auto& op : ins.operands )
			{
				if ( op.type == X86_OP_REG )
				{
					if ( op.access & CS_AC_READ )
						reads[ vtil_registers.extend( op.reg ) ] = true;
					if ( op.access & CS_AC_WRITE )
						writes[ vtil_registers.extend( op.reg ) ] = true;
				}
				else if ( op.type == X86_OP_MEM )
				{
					for ( auto reg : {
						op.mem.base,
						op.mem.index } )
					{
						if ( reg != X86_REG_INVALID )
							reads[ vtil_registers.extend( reg ) ] = true;
					}

					mem_read |= op.access & CS_AC_READ;
					mem_write |= op.access & CS_AC_WRITE;
				}
			}

			// Consider the side effects of the register execution
			// (With the exception of RSP and RFLAGS)
			//
			for ( uint16_t _r : ins.regs_read )
			{
				x86_reg r = vtil_registers.extend( _r );
				if ( r == X86_REG_EFLAGS || r == X86::REG::SP ) continue;
				// CPUID:RCX exception
				if ( ins.id == X86_INS_CPUID && r == X86::REG::CX ) continue;
				reads[ r ] = true;
			}

			for ( uint16_t _r : ins.regs_write )
			{
				x86_reg r = vtil_registers.extend( _r );
				if ( r == X86_REG_EFLAGS || r == X86::REG::SP ) continue;
				writes[ r ] = true;
			}

			// If we write to memory OR a traced register, 
			// all of the registers we read should be traced
			//
			bool should_be_tracked = mem_write;
			for ( auto& p : traced )
			{
				if ( writes[ p.first ] )
					should_be_tracked |= p.second;
			}

			// If instruction is tracked:
			//
			if ( should_be_tracked )
			{
				// Stop tracing the registers we wrote to
				//
				for ( auto& p : writes )
					traced[ p.first ] &= !p.second;

				// Start tracing the registers we read from
				//
				for ( auto& p : reads )
					traced[ p.first ] |= p.second;

				// Log the current instruction
				//
				is_reduced.stream.push_back( is.stream[ i ] );
			}
		}

		// puts(is.normalize().to_string().c_str());
		// puts(is_reduced.normalize().to_string().c_str());

		// Replace input stream with the reduced stream
		//
		is.stream = is_reduced.stream;
		is.normalize();
	}

	// Deduces the virtual register key from the given instruction stream
	//
	void update_vrk( vm_state* state, const instruction_stream& is )
	{
#if _M_X64 || __x86_64__
		// Find new rolling key register, ( xor [rsp], r64 )
		//
		int i_enc_end = is.next( X86_INS_XOR, { X86_OP_MEM, X86_OP_REG }, [ & ] ( const vtil_instruction& ins )
		{
			return
				ins.operands[ 0 ].mem.base == X86::REG::SP &&
				ins.operands[ 0 ].mem.disp == 0 &&
				ins.operands[ 0 ].mem.index == X86_REG_INVALID &&
				ins.operands[ 0 ].mem.scale == 1;
		} );
		fassert( i_enc_end != -1 );

		// Find first pop r64, so r64 = [rsp], the next key
		// 
		int i_pop = is.next( X86_INS_POP, { X86_OP_REG }, i_enc_end );
		fassert( i_pop != -1 );
		state->reg_vrk = is[ i_pop ].operands[ 0 ].reg;
#else

		state->reg_vrk = X86_REG_EBX;

#endif
	}

	// Deduces the virtual instruction stream direction from the given instruction stream
	//
	void update_vip_direction( vm_state* state, const instruction_stream& is )
	{
		// Define the filters based on the way VIP stream is read
		//
		auto fwd_filter = [ & ] ( const vtil_instruction& ins )
		{
			// Type #1:
			// [ add rbp, 4 ]
			//
			if ( ins.is( X86_INS_ADD, { X86_OP_REG, X86_OP_IMM } ) )
			{
				return ins.operands[ 0 ].reg == state->reg_vip &&
					ins.operands[ 1 ].imm == 4;;
			}
			// Type #2:
			// [ lea rbp, [rbp+4] ]
			//
			else if ( ins.is( X86_INS_LEA, { X86_OP_REG, X86_OP_MEM } ) )
			{
				return
					ins.operands[ 0 ].reg == state->reg_vip &&
					ins.operands[ 1 ].mem.disp == 4 &&
					ins.operands[ 1 ].mem.scale == 1 &&
					ins.operands[ 1 ].mem.base == state->reg_vip &&
					ins.operands[ 1 ].mem.index == X86_REG_INVALID;
			}
			return false;
		};
		auto bwd_filter = [ & ] ( const vtil_instruction& ins )
		{
			// Type #1:
			// [ sub rbp, 4 ]
			//
			if ( ins.is( X86_INS_SUB, { X86_OP_REG, X86_OP_IMM } ) )
			{
				return ins.operands[ 0 ].reg == state->reg_vip &&
					ins.operands[ 1 ].imm == 4;
			}
			// Type #2:
			// [ lea rbp, [rbp-4] ]
			//
			else if ( ins.is( X86_INS_LEA, { X86_OP_REG, X86_OP_MEM } ) )
			{
				return
					ins.operands[ 0 ].reg == state->reg_vip &&
					ins.operands[ 1 ].mem.disp == -4 &&
					ins.operands[ 1 ].mem.scale == 1 &&
					ins.operands[ 1 ].mem.base == state->reg_vip &&
					ins.operands[ 1 ].mem.index == X86_REG_INVALID;
			}
			return false;
		};

		// Find the first instances for both where possible
		//
		auto i_fwd = is.next( fwd_filter );
		auto i_bwd = is.next( bwd_filter );

		// Deduct the way instruction stream is iterated
		//
		if ( i_fwd == -1 && i_bwd != -1 ) state->dir_vip = -1;
		else if ( i_fwd != -1 && i_bwd == -1 ) state->dir_vip = +1;
		else if ( i_fwd != -1 && i_bwd != -1 ) state->dir_vip = i_fwd > i_bwd ? -1 : +1;
		else unreachable();
	}

	// Finds the self-reference point from the given instruction stream if relevant
	//
	std::optional<uint64_t> find_self_ref( vm_state* state, const instruction_stream& is, int index )
	{

#if _M_X64 || __x86_64__

		// Find the first LEA r64, [$]
		//
		int i_ref_self = is.next( X86_INS_LEA, { X86_OP_REG, X86_OP_MEM }, [ & ] ( const vtil_instruction& ins )
		{
			return
				ins.operands[ 1 ].mem.disp == -7 &&
				ins.operands[ 1 ].mem.scale == 1 &&
				ins.operands[ 1 ].mem.base == X86_REG_RIP &&
				ins.operands[ 1 ].mem.index == X86_REG_INVALID;
		}, index );
#else
		// Find the first lea r32, IMM (self eip)
        //
		int i_ref_self = is.next(X86_INS_LEA, { X86_OP_REG, X86_OP_MEM }, [&](const vtil_instruction& ins)
			{
				return
					ins.operands[1].mem.disp == state->img->get_mapped_image_base() + ins.address &&
					ins.operands[1].mem.scale == 1 &&
					ins.operands[1].mem.base == X86_REG_INVALID &&
					ins.operands[1].mem.index == X86_REG_INVALID;
			}, index);
#endif

		if ( i_ref_self == -1 ) return {};
		else return { is[ i_ref_self ].address };
	}

	// Parses VMENTER subroutine and extracts the vm information, entry point of the
	// virtualized routine, rolling key 0 value, and describes the push order of registers.
	// - Pushing reloc at last is left to the caller.
	//
	std::pair<std::vector<vtil::operand>, vtil::vip_t> parse_vmenter( vm_state* vstate, uint32_t rva_ep )
	{
		// Unroll the stream
		//
		instruction_stream is = deobfuscate( vstate->img, rva_ep );

		// Instruction stream should start with a 32 bit constant being pushed which is the 
		// encrypted offset to the beginning of the virtual instruction stream
		//
		fassert( is[ 0 ].is( X86_INS_PUSH, { X86_OP_IMM } ) );
		uint32_t vip_offset_encrypted = (uint32_t)is[ 0 ].operands[ 0 ].imm;

		// Resolve the real stack composition
		//
		x86_reg reg_reloc_delta;
		std::vector<vtil::operand> stack =
		{
			{ vip_offset_encrypted, vtil::arch::bit_count }, // push vmp_key
			{ vstate->img->get_real_image_base() + is[ 0 ].address + is[ 0 ].bytes.size() + 5, vtil::arch::bit_count } // call vmp0.xxx, return ip
		};

#if _M_X64 || __x86_64__
		constexpr auto is64 = true;

		for ( int i = 0;; i++ )
		{
			// If PUSH R64
			if ( is[ i ].is( X86_INS_PUSH, { X86_OP_REG } ) )
				stack.push_back( is[ i ].operands[ 0 ].reg );

			// If PUSHFQ
			if ( is[ i ].is( X86::INS::PUSHF, {} ) )
				stack.push_back( vtil::REG_FLAGS );

			// End of pushed registers, reset stream
			if ( is[ i ].is( X86_INS_MOVABS, { X86_OP_REG,  X86_OP_IMM } ) ) {
				reg_reloc_delta = is[ i ].operands[ 0 ].reg;
				is.erase( i - 1 );
				break;
			}
		}

		fassert( stack.size() == ( 16 + 2 ) );

#else
		constexpr auto is64 = false;

		for (int i = 0;; i++)
		{
			// If PUSH R32
			if ( is[ i ].is( X86_INS_PUSH, { X86_OP_REG } ) )
				stack.push_back( is[ i ].operands[ 0 ].reg );

			// If PUSHFD
			if ( is[ i ].is( X86::INS::PUSHF, {} ) )
				stack.push_back( vtil::REG_FLAGS );

			// End of pushed registers, reset stream
			if ( stack.size() == 8 + 2 && 
				 is[ i ].is( X86_INS_MOV, { X86_OP_REG,  X86_OP_IMM } ) ) {

				if ( is.next( X86_INS_PUSH, { X86_OP_REG }, [ & ]( const vtil_instruction& ins )
						{
							return ins.operands[ 0 ].reg == is[ i ].operands[ 0 ].reg;
						}, i) != -1 )
				{
					reg_reloc_delta = is[ i ].operands[ 0 ].reg;
					is.erase( i - 1 );
					break;
				}
			}
		}

		fassert( stack.size() == ( 8 + 2 ) );
#endif

		// Resolve the stack composition
		//
		auto ep_vip_offset = uint32_t (stack.size() * (is64 ? 8 : 4));

		// Resolve the register mapped to be VSP
		//
		int i_save_registers_id = 0;
		while ( true )
		{
			// Find the first MOV r64, RSP
			//
			i_save_registers_id = is.next( X86_INS_MOV, { X86_OP_REG, X86_OP_REG }, [ & ] ( const vtil_instruction& ins )
			{
				return ins.operands[ 1 ].reg == X86::REG::SP;
			}, i_save_registers_id );
			fassert( i_save_registers_id != -1 );
			vstate->reg_vsp = is[ i_save_registers_id ].operands[ 0 ].reg;

			// Check for any false positives, vsp should be assigned only once.
			//
			auto [vsp_ss, vsp_dep] = is.trace( vstate->reg_vsp, (int)is.stream.size() - 1 );
			if ( vsp_ss.stream.size() != 1 ||
				 vsp_ss[ 0 ].address != is[ i_save_registers_id ].address )
			{
				i_save_registers_id++;
				continue;
			}
			break;
		}

		// Find the first stack access ( For example: mov rsi, [rsp+90h], rsi = VENTER pushed imm32 )
		//
		int i_load_vip_id = is.next( X86_INS_MOV, { X86_OP_REG, X86_OP_MEM }, [ & ] ( const vtil_instruction& ins )
		{
			return
				ins.operands[ 1 ].mem.base == X86::REG::SP &&
				ins.operands[ 1 ].mem.disp == ep_vip_offset;
		} );
		fassert( i_load_vip_id != -1 );
		vstate->reg_vip = is[ i_load_vip_id ].operands[ 0 ].reg;

		// Find the first ADD r, x or LEA r, [r+x] ( For example: lea rsi, [rsi+rbp], which add vip with reloc_delta )
		//
		auto vip_d_epi_filter = [ & ] ( const vtil_instruction& ins )
		{
			if ( ins.is( X86_INS_ADD, { X86_OP_REG, X86_OP_REG } ) )
			{
				return ins.operands[ 0 ].reg == vstate->reg_vip &&
					ins.operands[ 1 ].reg == reg_reloc_delta;
			}
			else if ( ins.is( X86_INS_LEA, { X86_OP_REG, X86_OP_MEM } ) )
			{
				return ins.operands[ 0 ].reg == vstate->reg_vip &&
					ins.operands[ 1 ].mem.disp == 0 &&
					ins.operands[ 1 ].mem.scale == 1 &&
					( ( ins.operands[ 1 ].mem.base == reg_reloc_delta &&
					  ins.operands[ 1 ].mem.index == vstate->reg_vip ) ||
					  ( ins.operands[ 1 ].mem.index == reg_reloc_delta &&
					  ins.operands[ 1 ].mem.base == vstate->reg_vip ) );
			}
			return false;
		};
		int i_add_base_id = is.next( vip_d_epi_filter, i_load_vip_id );
		fassert( i_add_base_id != -1 );


		// Find value of reloc_delta, eg: mov edx, 547E0000h
		//
#if _M_X64 || __x86_64__
		constexpr auto load_reloc_delta_ins = X86_INS_MOVABS;
#else
		constexpr auto load_reloc_delta_ins = X86_INS_MOV;
#endif
		int i_load_reloc_delta_id = is.prev( load_reloc_delta_ins, { X86_OP_REG, X86_OP_IMM }, [ & ] ( const vtil_instruction& ins )
		{
			return ins.operands[ 0 ].reg == reg_reloc_delta;
		}, i_add_base_id );
		fassert(i_load_reloc_delta_id != -1);

		vstate->reloc_delta = (size_t) is[ i_load_reloc_delta_id ].operands[ 1 ].imm;


		// Extract the VIP decryption code and wrap with a lambda
		//
		auto [vip_dec_ss, vip_dec_ss_dep] = is.trace(
			vstate->reg_vip,
			i_add_base_id - 1,
			i_load_vip_id + 1
		);
		fassert( vip_dec_ss_dep.empty() );




		// Delete the stream before i_add_base_id
		//
		is.erase( i_add_base_id );

		// Decrypt the VIP entry point
		//
		std::vector<uint8_t> raw_stream = vip_dec_ss.to_raw();
		std::vector<uint8_t, mem::rwx_allocator<uint8_t>> exec_stream = { raw_stream.begin(), raw_stream.end() };
		exec_stream.push_back( 0xC3 );
		emulator emu = {};
		emu.set( vstate->reg_vip, vip_offset_encrypted );
		emu.invoke( exec_stream.data() );
#if _M_X64 || __x86_64__
		static constexpr uint64_t image_base_offset = 0x100000000;
#else
		static constexpr uint64_t image_base_offset = 0;
#endif
		uint32_t rva_vip0 = uint32_t( emu.get( vstate->reg_vip ) + vstate->reloc_delta + image_base_offset - vstate->img->get_real_image_base() );

		// Find our reference point, a instrument to get RIP
		// ( VMP will calc new rva, and add with RIP at ref_point to jmp to next handler )
		//
		auto ref_point = find_self_ref( vstate, is );
		fassert( ref_point.has_value() );

		// Update VIP direction
		//
		update_vip_direction( vstate, is );

		// Update rolling key register
		//
		update_vrk( vstate, is );

		// Find the first decryption block
		//
		auto [i_rkeyb, rkeyb] = extract_next_rkey_block( vstate, is );
		fassert( i_rkeyb != -1 );

		// Skip to next handler
		//
		vstate->next( rkeyb, rva_vip0, (uint32_t) ref_point.value() );

		// Return the content pushed on stack in order
		//
		return { stack, rva_vip0 };
	}

	// Parses the VMEXIT subroutine and extracts the order registers are pop'd from the stack.
	//
	std::vector<vtil::operand> parse_vmexit( vm_state* vstate, const instruction_stream& is )
	{
		// Resolve popped registers
		//
		std::vector<vtil::operand> stack;
		for ( int i = 0;; i++ )
		{
			// If POP R64
			if ( is[ i ].is( X86_INS_POP, { X86_OP_REG } ) )
				stack.push_back( is[ i ].operands[ 0 ].reg );
			// If POPFW
			if ( is[ i ].is( X86::INS::POPF, {} ) )
				stack.push_back( vtil::REG_FLAGS );
			// End of pushed registers, reset stream
			if ( is[ i ].is( X86_INS_RET, {} ) )
				return stack;
		}
		unreachable();
	}

	// Parses swapping vm of context/registers, returns newly extracted rkey blocks
	//
	std::vector<rkey_block> parse_vmswap( vm_state* vstate, instruction_stream& is, instruction_stream& prefix_out )
	{
		// #################################################
		// All of the constant VM registers will be mutated
		// - [VIP => VSP => VRK] in order
		// #################################################

		// Make sure this instruction stream abides by our current pattern
		//
		auto& ins_read_vsp = is[ 0 ];
		if ( ins_read_vsp.is( X86_INS_MOV, { X86_OP_REG, X86_OP_MEM } ) )
		{
			x86_reg vip_from = ins_read_vsp.operands[ 0 ].reg;

			// Find the mutation end point
			//
#if _M_X64 || __x86_64__
			constexpr auto mut_end_ins = X86_INS_MOVABS;
#else
			constexpr auto mut_end_ins = X86_INS_MOV;
#endif
			int i_mut_end = is.next( mut_end_ins, { X86_OP_REG, X86_OP_IMM } , [ & ] ( const vtil_instruction& ins )
			{
				return ins.operands[ 0 ].size == vtil::arch::size && 
					ins.operands[ 1 ].imm == vstate->reloc_delta;
			} );
			if ( i_mut_end != -1 )
			{
				// Map all registers and resolve their final value
				//
				std::map<x86_reg, std::pair<int, x86_reg>> register_mappings;
				for ( int i = 0; i < X86_REG_ENDING; i++ )
				{
					x86_reg r = vtil_registers.extend( ( x86_reg ) i );
					register_mappings[ r ] = { 0, r };
				}

				for ( int i = 1; i < i_mut_end; i++ )
				{
					auto& ins = is[ i ];

					// Make sure it matches our instruction type and extract registers
					//
					if ( ins.operands.size() != 2 ) continue;
					if ( ins.operands[ 0 ].size != vtil::arch::size ) continue;

					if ( ins.is( X86_INS_MOV, { X86_OP_REG, X86_OP_REG } ) )
					{
						x86_reg r1 = ins.operands[ 0 ].reg;
						x86_reg r2 = ins.operands[ 1 ].reg;
						register_mappings[ r1 ] = { i, register_mappings[ r2 ].second };
					}
					else if ( ins.is( X86_INS_XCHG, { X86_OP_REG, X86_OP_REG } ) )
					{
						x86_reg r1 = ins.operands[ 0 ].reg;
						x86_reg r2 = ins.operands[ 1 ].reg;
						std::swap( register_mappings[ r1 ].second, register_mappings[ r2 ].second );
						register_mappings[ r1 ].first = i;
						register_mappings[ r2 ].first = i;
					}
				}

				// Resolve all inheritance
				//
				auto inherits_from = [ & ] ( x86_reg reg )
				{
					std::vector<std::pair<int, x86_reg>> inheritance;

					for ( auto& pair : register_mappings )
					{
						if ( pair.second.first != 0 &&
							 pair.second.second == reg )
							inheritance.push_back( { pair.second.first, pair.first } );
					}

					std::sort( inheritance.begin(), inheritance.end() );
					return inheritance;
				};

				// Assert the pattern is abided by and map the new registers
				//
				auto vip_inh = inherits_from( vip_from );
				auto vsp_inh = inherits_from( vstate->reg_vsp );
				if ( vip_inh.size() == 1 ) vip_inh.insert( vip_inh.begin(), { 0, vip_from } );
				fassert( vip_inh.size() >= 2 );

				// Reduce the chunk before mutating the VM parameters
				//
				int pfx_end = vip_inh[ 0 ].first;
				if ( vsp_inh.size() ) pfx_end = std::max( pfx_end, vsp_inh.back().first );
				if ( pfx_end == 0 && vip_inh.size() >= 2 ) pfx_end = vip_inh[ 1 ].first;

				prefix_out.stream = { is.stream.begin(), is.stream.begin() + pfx_end };

				// Strip any assigning pre-mutation
				//
				for ( int i = (int) prefix_out.size() - 1; i >= 0; i-- )
				{
					if ( prefix_out[ i ].is( X86_INS_MOV, { X86_OP_REG, X86_OP_REG } ) ||
						 prefix_out[ i ].is( X86_INS_XCHG, { X86_OP_REG, X86_OP_REG } ) )
						prefix_out.stream.erase( prefix_out.stream.begin() + i );
				}

				reduce_chunk( vstate, prefix_out, {}, false );

				// Assign the new registers
				//
				vstate->reg_vip = vip_inh[ 0 ].second;
				vstate->reg_vsp = vsp_inh.empty() ? vstate->reg_vsp : vsp_inh.back().second;
				vstate->reg_vrk = vip_inh[ 1 ].second;

				// Erase all instruction prior to the mutation so the 
				// IL conversion does not get confused
				//
				is.erase( i_mut_end );

				// Update instruction stream direction
				update_vip_direction( vstate, is );

			}
		}

		return extract_rkey_blocks( vstate, is );
	}
};
