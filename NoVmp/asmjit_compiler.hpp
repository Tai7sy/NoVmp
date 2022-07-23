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
#pragma once
#if _M_X64 || __x86_64__
#include <vtil/amd64>
#define COMPILER_ARCH amd64
#else
#include <vtil/x86>
#define COMPILER_ARCH x86
#endif
#include <vtil/arch>
#include <vtil/compiler>
#include <vtil/io>
#include <string>
#include <set>
#include <unordered_map>
#include <asmjit/x86.h>
#include <asmjit/x86/x86operand.h>

using namespace asmjit;

namespace ins
{
	using namespace vtil::ins;
};

static void compile( vtil::basic_block* basic_block, struct routine_state* state );

struct routine_state
{
	std::unordered_map<vtil::vip_t, Label> label_map;
	std::set<vtil::vip_t> is_compiled;
	std::unordered_map<vtil::operand::register_t, x86::Gp> reg_map;
	x86::Gp flags_reg;
	x86::Compiler& cc;
	Imm image_base;
	uint32_t rva;

	routine_state( x86::Compiler& cc, uintptr_t image_base, uint32_t rva )
		: cc( cc )
		, image_base( image_base )
		, rva( rva )
	{
	}

	Label get_label( vtil::vip_t address )
	{
		if ( label_map.count( address ) )
		{
			return label_map.at( address );
		}
		else
		{
			// TODO: Create a namedLabel
			//
			Label label = cc.newLabel();
			label_map.insert( { address, label } );
			return label;
		}
	}

	x86::Gp reg_for_size( vtil::operand const& operand )
	{
		switch ( operand.bit_count() )
		{
			// TODO: Handle sized register access
			//
			case 1:
			case 8:
			case 16:
			case 32:
			case 64:
				return cc.newGpq();
			default:
				unreachable();
		}
	}

	x86::Gp tmp_imm( vtil::operand const& reg )
	{
		x86::Gp tmp = reg_for_size( reg );
		cc.mov( tmp, reg.imm().ival );
		return tmp;
	}

	x86::Gp get_reg( vtil::operand::register_t const& operand )
	{
		using vtil::logger::log;

		// TODO: Handle bit selectors on registers

		log( "get_reg: %s\n", operand.to_string() );
		if ( operand.is_physical() )
		{
			log( "\tis_physical\n" );
			// Transform the VTIL register into an AsmJit one.
			//
			// TODO: This shouldnt be a separate condition, but just
			// in the same switch
			//
			if ( operand.is_stack_pointer() )
			{
				log( "\t\tis_stack_pointer\n" );
				// TODO: this might cause problems, the stack
				// of the program and of VTIL are shared
				//
				return x86::rsp;
			}
			else if ( operand.is_flags() )
			{
				log( "\t\tis_flags: %d\n", flags_reg.isValid() );
				if ( !flags_reg.isValid() )
				{
					flags_reg = cc.newGpq();
				}

				return flags_reg;
			}
			else
			{
				log( "\t\tmachine_register: %s\n", vtil::amd64::name( operand.combined_id ) );
				switch ( operand.combined_id )
				{
					case X86_REG_R8:
						return x86::r8;
					case X86_REG_R9:
						return x86::r9;
					case X86_REG_R10:
						return x86::r10;
					case X86_REG_R11:
						return x86::r11;
					case X86_REG_R12:
						return x86::r12;
					case X86_REG_R13:
						return x86::r13;
					case X86_REG_R14:
						return x86::r14;
					case X86_REG_R15:
						return x86::r15;
					case X86_REG_RSI:
						return x86::rsi;
					case X86_REG_RBP:
						return x86::rbp;
					case X86_REG_RDI:
						return x86::rdi;
					case X86_REG_RAX:
						return x86::rax;
					case X86_REG_RBX:
						return x86::rbx;
					case X86_REG_RCX:
						return x86::rcx;
					case X86_REG_RDX:
						return x86::rdx;
					default:
						abort();
				}
			}
		}
		else
		{
			log( "\tis_virtual\n" );

			if ( operand.is_image_base() )
			{
				log( "\t\tis_image_base\n" );
				x86::Gp base_reg = reg_for_size( operand );
				cc.mov( base_reg, image_base );
				return base_reg;
			}
			else if ( operand.is_flags() )
			{
				log( "\t\tis_flags\n" );
				abort();
			}
			// Grab the register from the map, or create and insert otherwise.
			//
			else if ( reg_map.count( operand ) )
			{
				return reg_map[ operand ];
			}
			else
			{
				x86::Gp reg = reg_for_size( operand );
				reg_map[ operand ] = reg;
				return reg;
			}
		}
	}
};

using fn_instruction_compiler_t = std::function<void( const vtil::il_iterator&, routine_state* )>;
static const std::map<vtil::instruction_desc, fn_instruction_compiler_t> handler_table = {
	{
		ins::ldd,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto dest = instr->operands[ 0 ].reg();
			auto src = instr->operands[ 1 ].reg();
			auto offset = instr->operands[ 2 ].imm();

			// FIXME: Figure out how to determine if the offset is signed or not
			//
			state->cc.mov( state->get_reg( dest ), x86::ptr( state->get_reg( src ), offset.ival ) );
		},
	},
	{
		ins::str,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto base = instr->operands[ 0 ].reg();
			auto offset = instr->operands[ 1 ].imm();
			auto v = instr->operands[ 2 ];

			// FIXME: There is an issue here where it cannot deduce the size
			// of the move?
			//

			auto reg_base = state->get_reg( base );
			x86::Mem dest;
			switch ( v.bit_count() )
			{
			case 8:
				dest = x86::ptr_8( reg_base, offset.ival );
				break;
			case 16:
				dest = x86::ptr_16( reg_base, offset.ival );
				break;
			case 32:
				dest = x86::ptr_32( reg_base, offset.ival );
				break;
			case 64:
				dest = x86::ptr_64( reg_base, offset.ival );
				break;
			default:
				unreachable();
			}

			if ( v.is_immediate() )
			{
				state->cc.mov( dest, v.imm().ival );
			}
			else
			{
				state->cc.mov( dest, state->get_reg( v.reg() ) );
			}
		},
	},
	{
		ins::mov,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto dest = instr->operands[ 0 ].reg();
			auto src = instr->operands[ 1 ];

			if ( src.is_immediate() )
			{
				state->cc.mov( state->get_reg( dest ), src.imm().ival );
			}
			else
			{
				state->cc.mov( state->get_reg( dest ), state->get_reg( src.reg() ) );
			}
		},
	},
	{
		ins::sub,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto dest = instr->operands[ 0 ].reg();
			auto src = instr->operands[ 1 ];

			if ( src.is_immediate() )
			{
				x86::Gp tmp = state->reg_for_size( src );
				state->cc.mov( tmp, src.imm().ival );
				state->cc.sub( state->get_reg( dest ), tmp );

				// AsmJit shits its pants when I use this, so we move to a temporary
				// instead. TODO: Investigate
				// state->cc.sub( state->get_reg( dest ), src.imm().ival );
				//
			}
			else
			{
				state->cc.sub( state->get_reg( dest ), state->get_reg( src.reg() ) );
			}
		},
	},
	{
		ins::add,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto lhs = instr->operands[ 0 ].reg();
			auto rhs = instr->operands[ 1 ];

			if ( rhs.is_immediate() )
			{
				x86::Gp tmp = state->reg_for_size( rhs );
				state->cc.mov( tmp, rhs.imm().ival );
				state->cc.add( state->get_reg( lhs ), tmp );

				// See note on sub
				//
			}
			else
			{
				state->cc.add( state->get_reg( lhs ), state->get_reg( rhs.reg() ) );
			}
		},
	},
	{
		ins::mul,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto lhs = instr->operands[ 0 ].reg();
			auto rhs = instr->operands[ 1 ];

			x86::Gp vHi = state->reg_for_size( lhs );

			if ( rhs.is_immediate() )
			{
				x86::Gp tmp = state->reg_for_size( rhs );
				state->cc.mov( tmp, rhs.imm().ival );
				// mul rdx, rax, rcx
				state->cc.mul( vHi, state->get_reg( lhs ), tmp );
			}
			else
			{
				state->cc.mul( vHi, state->get_reg( lhs ), state->get_reg( rhs.reg() ) );
			}
		},
	},
	{
		ins::mulhi,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto lhs = instr->operands[ 0 ].reg();
			auto rhs = instr->operands[ 1 ];

			x86::Gp vHi = state->reg_for_size( lhs );

			if ( rhs.is_immediate() )
			{
				x86::Gp tmp = state->reg_for_size( rhs );
				state->cc.mov( tmp, rhs.imm().ival );
				// mul rdx, rax, rcx
				state->cc.mul( vHi, state->get_reg( lhs ), tmp );
			}
			else
			{
				state->cc.mul( vHi, state->get_reg( lhs ), state->get_reg( rhs.reg() ) );
			}

			state->cc.mov( state->get_reg( lhs ), state->cc.newGpq() );

		},
	},
	{
		ins::imul,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto lhs = instr->operands[ 0 ].reg();
			auto rhs = instr->operands[ 1 ];

			x86::Gp vHi = state->reg_for_size( lhs );

			if ( rhs.is_immediate() )
			{
				x86::Gp tmp = state->reg_for_size( rhs );
				state->cc.mov( tmp, rhs.imm().ival );
				// imul rdx, rax, rcx
				state->cc.imul( vHi, state->get_reg( lhs ), tmp );
			}
			else
			{
				state->cc.imul( vHi, state->get_reg( lhs ), state->get_reg( rhs.reg() ) );
			}
		},
	},
	{
		ins::imulhi,
		[ ] ( const vtil::il_iterator& instr, routine_state* state ) {
			auto lhs = instr->operands[ 0 ].reg();
			auto rhs = instr->operands[ 1 ];

			x86::Gp vHi = state->reg_for_size( lhs );

			if ( rhs.is_immediate() )
			{
				x86::Gp tmp = state->reg_for_size( rhs );
				state->cc.mov( tmp, rhs.imm().ival );
				// imul rdx, rax, rcx
				state->cc.imul( vHi, state->get_reg( lhs ), tmp );
			}
			else
			{
				state->cc.imul( vHi, state->get_reg( lhs ), state->get_reg( rhs.reg() ) );
			}

			state->cc.mov( state->get_reg( lhs ), vHi );

		},
	},
	{
		ins::js,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			auto cond = it->operands[ 0 ].reg();
			auto dst_1 = it->operands[ 1 ];
			auto dst_2 = it->operands[ 2 ];

			fassert( dst_1.is_immediate() && dst_2.is_immediate() );

			// TODO: We should check if the block is compiled in order to avoid the
			// jump here, but I think the optimizer removes this?
			//
			state->cc.test( state->get_reg( cond ), state->get_reg( cond ) );

			state->cc.jnz( state->get_label( dst_1.imm().uval ) );
			state->cc.jmp( state->get_label( dst_2.imm().uval ) );

			for ( vtil::basic_block* destination : it.block->next )
			{
				if ( !state->is_compiled.count( destination->entry_vip ) )
					compile( destination, state );
			}
		},
	},
	{
		ins::jmp,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			vtil::debug::dump( *it );
			if ( it->operands[ 0 ].is_register() )
			{
				const vtil::operand::register_t cond = it->operands[ 0 ].reg();

				for ( vtil::basic_block* destination : it.block->next )
				{
					state->cc.cmp( state->get_reg( cond ), destination->entry_vip );
					state->cc.je( state->get_label( destination->entry_vip ) );

					if ( !state->is_compiled.count( destination->entry_vip ) )
						compile( destination, state );
				}
			}
			else
			{
				fassert( it->operands[ 0 ].is_immediate() );

				auto dest = it.block->next[ 0 ]->entry_vip;

				state->cc.jmp( state->get_label( dest ) );

				if ( !state->is_compiled.count( dest ) )
					compile( it.block->next[ 0 ], state );
			}
		},
	},
	{
		ins::vexit,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {

			if ( it->operands[ 0 ].is_immediate() )
			{
				state->cc.jmp( it->operands[ 0 ].imm().ival );
			}
			// If register:
			//
			else
			{
				state->cc.jmp( state->get_reg( it->operands[ 0 ].reg() ) );
			}

			// state->cc.ret();
		},
	},
	{
		ins::vxcall,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			// TODO: This should be a call, but you need to create
			// a call, etc. for the register allocator
			// if ( it->operands[ 0 ].is_immediate() )
			// {
			//     state->cc.jmp( it->operands[ 0 ].imm().uval );
			// }
			// else
			// {
			//     state->cc.jmp( state->get_reg( it->operands[ 0 ].reg() ) );
			// }
			//

			// If immmediate:
			//
			if ( it->operands[ 0 ].is_immediate() )
			{
				state->cc.call( it->operands[ 0 ].imm().uval );
			}
			else
			{
				auto lhs = it->operands[ 0 ].reg();
				state->cc.call( state->get_reg( lhs ) );
			}

			auto dest = it.block->next[ 0 ]->entry_vip;

			// Jump to next block.
			//
			state->cc.jmp( state->get_label( dest ) );

			if ( !state->is_compiled.count( dest ) )
				compile( it.block->next[ 0 ], state );
		},
	},
	{
		ins::bshl,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			auto dest = it->operands[ 0 ].reg();
			auto shift = it->operands[ 1 ];

			if ( shift.is_immediate() )
			{
				state->cc.shl( state->get_reg( dest ), shift.imm().ival );
			}
			else
			{
				state->cc.shl( state->get_reg( dest ), state->get_reg( shift.reg() ) );
			}
		},
	},
	{
		ins::bshr,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			auto dest = it->operands[ 0 ].reg();
			auto shift = it->operands[ 1 ];

			if ( shift.is_immediate() )
			{
				state->cc.shr( state->get_reg( dest ), shift.imm().ival );
			}
			else
			{
				state->cc.shr( state->get_reg( dest ), state->get_reg( shift.reg() ) );
			}
		},
	},
	{
		ins::band,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			auto dest = it->operands[ 0 ].reg();
			auto bit = it->operands[ 1 ];

			if ( bit.is_immediate() )
			{
				state->cc.and_( state->get_reg( dest ), state->tmp_imm( bit ) );
			}
			else
			{
				state->cc.and_( state->get_reg( dest ), state->get_reg( bit.reg() ) );
			}
		},
	},
	{
		ins::bor,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			auto lhs = it->operands[ 0 ].reg();
			auto rhs = it->operands[ 1 ];

			if ( rhs.is_immediate() )
			{
				if ( rhs.imm().bit_count > 32 || rhs.imm().ival > 0x7FFFFFFF )
				{
					auto temp_reg = state->cc.newGpq();
					state->cc.mov( temp_reg, rhs.imm().ival );
					state->cc.or_( state->get_reg( lhs ), temp_reg );
				}
				else
					state->cc.or_( state->get_reg( lhs ), rhs.imm().ival );
			}
			else
			{
				state->cc.or_( state->get_reg( lhs ), state->get_reg( rhs.reg() ) );
			}
		},
	},
	{
		ins::bxor,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			auto lhs = it->operands[ 0 ].reg();
			auto rhs = it->operands[ 1 ];

			if ( rhs.is_immediate() )
			{
				state->cc.xor_( state->get_reg( lhs ), rhs.imm().ival );
			}
			else
			{
				state->cc.xor_( state->get_reg( lhs ), state->get_reg( rhs.reg() ) );
			}
		},
	},
	{
		ins::bnot,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			state->cc.not_( state->get_reg( it->operands[ 0 ].reg() ) );
		},
	},
	{
		ins::neg,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			state->cc.neg( state->get_reg( it->operands[ 0 ].reg() ) );
		},
	},
	{
		ins::vemit,
		[ ] ( const vtil::il_iterator& it, routine_state* state ) {
			auto data = it->operands[ 0 ].imm().uval;
			// TODO: Are we guarenteed that the registers used by these
			// embedded instructions are actually live at the point these are executed?
			//
			state->cc.embedUInt8( ( uint8_t ) data );
		},
	},
#define MAP_CONDITIONAL(instrT, opcode, ropcode)                                    \
		{                                                                               \
			ins::instrT, [](const vtil::il_iterator& instr, routine_state* state) {     \
				vtil::logger::log("1_is_imm: %d\n", instr->operands[0].is_immediate()); \
				vtil::logger::log("2_is_imm: %d\n", instr->operands[1].is_immediate()); \
				vtil::logger::log("3_is_imm: %d\n", instr->operands[2].is_immediate()); \
				if (instr->operands[1].is_immediate())                                  \
				{                                                                       \
					x86::Gp tmp = state->reg_for_size(instr->operands[1]);              \
					state->cc.mov(tmp, instr->operands[1].imm().ival);                   \
					state->cc.cmp(state->get_reg(instr->operands[2].reg()), tmp);       \
					state->cc.ropcode(state->get_reg(instr->operands[0].reg()));        \
				}                                                                       \
				else                                                                    \
				{                                                                       \
					if (instr->operands[2].is_immediate())                              \
					{                                                                   \
						x86::Gp tmp = state->reg_for_size(instr->operands[2]);          \
						state->cc.mov(tmp, instr->operands[2].imm().ival);               \
						state->cc.cmp(state->get_reg(instr->operands[1].reg()), tmp);   \
					}                                                                   \
					else                                                                \
					{                                                                   \
						state->cc.cmp(state->get_reg(instr->operands[1].reg()),         \
							state->get_reg(instr->operands[2].reg()));                  \
					}                                                                   \
					state->cc.ropcode(state->get_reg(instr->operands[0].reg()));        \
				}                                                                       \
			},                                                                          \
		}
		MAP_CONDITIONAL( tg, setg, setle ),
		MAP_CONDITIONAL( tge, setge, setl ),
		MAP_CONDITIONAL( te, sete, setne ),
		MAP_CONDITIONAL( tne, setne, sete ),
		MAP_CONDITIONAL( tle, setle, setg ),
		MAP_CONDITIONAL( tl, setl, setge ),
		MAP_CONDITIONAL( tug, seta, setbe ),
		MAP_CONDITIONAL( tuge, setae, setb ),
		MAP_CONDITIONAL( tule, setbe, seta ),
		MAP_CONDITIONAL( tul, setb, setae ),
	#undef MAP_CONDITIONAL
		{
			ins::ifs,
			[ ] ( const vtil::il_iterator& it, routine_state* state ) {
				auto dest = it->operands[ 0 ].reg();
				auto cc = it->operands[ 1 ];
				auto res = it->operands[ 2 ];

				state->cc.xor_( state->get_reg( dest ), state->get_reg( dest ) );
				// TODO: CC can be an immediate, how does that work?
				//
				state->cc.test( state->get_reg( cc.reg() ), state->get_reg( cc.reg() ) );

				if ( res.is_immediate() )
				{
					x86::Gp tmp = state->reg_for_size( res );
					state->cc.mov( tmp, res.imm().ival );
					state->cc.cmovnz( state->get_reg( dest ), tmp );
				}
				else
				{
					state->cc.cmovnz( state->get_reg( dest ), state->get_reg( res.reg() ) );
				}
			},
		},
		{ ins::vpinr, [ ] ( const vtil::il_iterator& it, routine_state* state )
			{
			} },
		{ ins::vpinw, [ ] ( const vtil::il_iterator& it, routine_state* state )
			{
			} },
		{ ins::vpinrm, [ ] ( const vtil::il_iterator& it, routine_state* state )
			{
			} },
		{ ins::vpinwm, [ ] ( const vtil::il_iterator& it, routine_state* state )
			{
			} },
};

static void compile( vtil::basic_block* basic_block, routine_state* state )
{
	Label L_entry = state->get_label( basic_block->entry_vip );
	state->cc.bind( L_entry );
	state->is_compiled.insert( basic_block->entry_vip );

	for ( auto it = basic_block->begin(); !it.is_end(); it++ )
	{
		vtil::debug::dump( *it );
		auto handler = handler_table.find( *it->base );
		if ( handler == handler_table.end() )
		{
			vtil::logger::log( "\n[!] ERROR: Unrecognized instruction '%s'\n\n", it->base->name );
			exit( 1 );
		}
		handler->second( it, state );
	}
}

class DemoErrorHandler : public ErrorHandler
{
public:
	void handleError( Error err, const char* message, BaseEmitter* origin ) override
	{
		std::cerr << "AsmJit error: " << message << "\n";
	}
};


namespace asmjit_compiler
{

	void test_compile( x86::Compiler& cc ) {
		x86::Gp var1 = cc.newInt64( "var1" );
		x86::Gp var2 = cc.newInt64( "var2" );

		FuncNode* funcNode = cc.addFunc( FuncSignatureT<void>() );

		cc.mov( var1, 0x1111 );
		cc.mov( var2, 0x2222 );
		cc.add( var1, var2 );
		cc.mov( x86::rcx, 1 );
		cc.call( var1 );

		cc.endFunc();
	}

	static std::vector<uint8_t> compile( vtil::routine * rtn_in, uint32_t rva, uintptr_t image_base )
	{
		JitRuntime rt;
		FileLogger logger( stdout );
		DemoErrorHandler errorHandler;
		CodeHolder code;

		code.init( rt.environment() );
		code.setErrorHandler( &errorHandler );

		code.setLogger( &logger );
		x86::Compiler cc( &code );


#if 1
		// test
		test_compile( cc );
#else

		cc.addFunc( FuncSignatureT<void>() );

		//TODO is that info available in the .VTIL file?
		//
		routine_state state( cc, image_base, rva );
		compile( rtn_in->entry_point, &state );

		cc.endFunc();
#endif

		cc.finalize();

		CodeBuffer& buffer = code.sectionById( 0 )->buffer();

		return std::vector<uint8_t>{ buffer.begin(), buffer.end() };
	}
};