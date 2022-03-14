/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 1990-2015 Hex-Rays
 *      ALL RIGHTS RESERVED.
 */

#ifndef __HEXRAYS_HPP
#define __HEXRAYS_HPP

#define CHECKED_BUILD
#include <pro.h>
#include <fpro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ieee.h>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <set>
#include <map>
#include <deque>
#include <queue>
#include <algorithm>

#ifdef __VC__
#pragma warning(push)
#pragma warning(disable:4062) // enumerator 'x' in switch of enum 'y' is not handled
#pragma warning(disable:4265) // virtual functions without virtual destructor
#endif

#define hexapi                ///< Public functions are marked with this keyword

class intseq_t;
class mbl_array_t;
class mblock_t;
class codegen_t;
struct vdui_t;
struct hexrays_failure_t;
struct mba_stats_t;
struct mlist_t;
typedef int mreg_t;     ///< Micro register

struct cfunc_t;
struct citem_t;
struct cexpr_t;
struct cinsn_t;
struct cblock_t;
struct cswitch_t;
struct carg_t;
struct carglist_t;

//-------------------------------------------------------------------------
/// Macro to declare standard inline comparison operators
#define DECLARE_COMPARISON_OPERATORS(type)                              \
  bool operator==(const type &r) const { return compare(r) == 0; }      \
  bool operator!=(const type &r) const { return compare(r) != 0; }      \
  bool operator< (const type &r) const { return compare(r) <  0; }      \
  bool operator> (const type &r) const { return compare(r) >  0; }      \
  bool operator<=(const type &r) const { return compare(r) <= 0; }      \
  bool operator>=(const type &r) const { return compare(r) >= 0; }

/// Macro to declare comparisons for our classes
/// All comparison operators call the compare() function which returns -1/0/1
#define DECLARE_COMPARISONS(type)    \
  DECLARE_COMPARISON_OPERATORS(type) \
  friend int compare(const type &a, const type &b) { return a.compare(b); } \
  int compare(const type &r) const

/// Operand locator.
struct operand_locator_t
{
private:
  //forbid the default constructor
  operand_locator_t(void) {}
public:
  ea_t ea;              ///< address of the original instruction
  int opnum;            ///< operand number in the instruction
  operand_locator_t(ea_t _ea, int _opnum) : ea(_ea), opnum(_opnum) {}
  DECLARE_COMPARISONS(operand_locator_t);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

//-------------------------------------------------------------------------
/// Number represenation.
/// This structure holds information about number format.
struct number_format_t
{
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  flags_t flags;          ///< ida flags, which describe number radix, enum, etc
  char opnum;             ///< operand number: 0..UA_MAXOP
  char props;             ///< properties: combination of NF_ bits (\ref NF_)
/// \defgroup NF_ Number format property bits
/// Used in number_format_t::props
//@{
#define NF_FIXED    0x01  ///< number format has been defined by the user
#define NF_NEGDONE  0x02  ///< temporary internal bit: negation has been performed
#define NF_BINVDONE 0x04  ///< temporary internal bit: inverting bits is done
#define NF_NEGATE   0x08  ///< The user asked to negate the constant
#define NF_BITNOT   0x10  ///< The user asked to invert bits of the constant
#define NF_STROFF   0x20  ///< internal bit: used as stroff, valid iff is_stroff()
//@}
  uchar serial;           ///< for enums: constant serial number
  char org_nbytes;        ///< original number size in bytes
  qstring type_name;      ///< for stroffs: structure for offsetof()\n
                          ///< for enums: enum name
  /// Contructor
  number_format_t(int _opnum=0)
    : flags(0), opnum(char(_opnum)), props(0), serial(0), org_nbytes(0) {}
  /// Get number radix
  /// \return 2,8,10, or 16
  int get_radix(void) const { return ::get_radix(flags, opnum); }
  /// Is number representation fixed?
  /// Fixed representation can not be modified by the decompiler
  bool is_fixed(void) const { return props != 0; }
  /// Is a hexadecimal number?
  bool is_hex(void) const { return ::is_numop(flags, opnum) && get_radix() == 16; }
  /// Is a decimal number?
  bool is_dec(void) const { return ::is_numop(flags, opnum) && get_radix() == 10; }
  /// Is a octal number?
  bool is_oct(void) const { return ::is_numop(flags, opnum) && get_radix() == 8; }
  /// Is a symbolic constant?
  bool is_enum(void) const { return ::is_enum(flags, opnum); }
  /// Is a character constant?
  bool is_char(void) const { return ::is_char(flags, opnum); }
  /// Is a structure field offset?
  bool is_stroff(void) const { return ::is_stroff(flags, opnum); }
  /// Is a number?
  bool is_numop(void) const { return !is_enum() && !is_char() && !is_stroff(); }
  /// Does the number need to be negated or bitwise negated?
  /// Returns true if the user requested a negation but it is not done yet
  bool needs_to_be_inverted(void) const
  {
    return (props & (NF_NEGATE|NF_BITNOT)) != 0      // the user requested it
        && (props & (NF_NEGDONE|NF_BINVDONE)) == 0;  // not done yet
  }
};

// Number formats are attached to (ea,opnum) pairs
typedef std::map<operand_locator_t, number_format_t> user_numforms_t;

//-------------------------------------------------------------------------
/// Base helper class to convert binary data structures into text.
/// Other classes are derived from this class.
struct vd_printer_t
{
  qstring tmpbuf;
  int hdrlines;         ///< number of header lines (prototype+typedef+lvars)
                        ///< valid at the end of print process
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \return the number of printed characters
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  AS_PRINTF(3, 4) virtual int hexapi print(int indent, const char *format,...);
  AS_PRINTF(3, 0) int vprint(int indent, const char *format, va_list);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

/// Helper class to convert cfunc_t into text.
struct vc_printer_t : public vd_printer_t
{
  const cfunc_t *func;          ///< cfunc_t to generate text for
  char lastchar;                ///< internal: last printed character
  /// Constructor
  vc_printer_t(const cfunc_t *f) : func(f), lastchar(0) {}
  /// Are we generating one-line text representation?
  /// \return \c true if the output will occupy one line without line breaks
  virtual bool idaapi oneliner(void) const { return false; }
};

/// Helper class to convert binary data structures into text and put into a file.
struct file_printer_t : public vd_printer_t
{
  FILE *fp;                     ///< Output file pointer
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \return the number of printed characters
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  AS_PRINTF(3, 4) int print(int indent, const char *format, ...);
  /// Constructor
  file_printer_t(FILE *_fp) : fp(_fp) {}
};

/// Helper class to convert cfunc_t into a text string
struct qstring_printer_t : public vc_printer_t
{
  bool with_tags;               ///< Generate output with color tags
  qstring &s;                   ///< Reference to the output string
  /// Constructor
  qstring_printer_t(const cfunc_t *f, qstring &_s, bool tags)
    : vc_printer_t(f), with_tags(tags), s(_s) {}
  /// Print.
  /// This function is called to generate a portion of the output text.
  /// The output text may contain color codes.
  /// \return the number of printed characters
  /// \param indent  number of spaces to generate as prefix
  /// \param format  printf-style format specifier
  AS_PRINTF(3, 4) int hexapi print(int indent, const char *format, ...);
  AS_PRINTF(3, 0) int vprint(int indent, const char *format, va_list);
};

//-------------------------------------------------------------------------
/// \defgroup type Type string related declarations
/// Type related functions and class.
//@{

/// Verify a type string.
/// \return true if type string is correct

bool hexapi is_type_correct(const type_t *ptr);


/// Is a small structure or union?
/// \return true if the type is a small UDT (user defined type).
///              Small UDTs fit into a register (or pair or registers) as a rule.

bool hexapi is_small_struni(const tinfo_t &tif);


/// Is definitely a non-boolean type?
/// \return true if the type is a non-boolean type (non bool and well defined)

bool hexapi is_nonbool_type(const tinfo_t &type);


/// Is a boolean type?
/// \return true if the type is a boolean type

bool hexapi is_bool_type(const tinfo_t &type);


/// Is a pointer or array type?
inline bool is_ptr_or_array(type_t t)
{
  return is_type_ptr(t) || is_type_array(t);
}

/// Is a pointer, array, or function type?
inline bool is_paf(type_t t)
{
  return is_ptr_or_array(t) || is_type_func(t);
}

/// Is struct/union/enum definition (not declaration)?
inline bool is_inplace_def(const tinfo_t &type)
{
  return type.is_decl_complex() && !type.is_typeref();
}

/// Calculate number of partial subtypes.
/// \return number of partial subtypes. The bigger is this number, the uglier is the type.

int hexapi partial_type_num(const tinfo_t &type);


/// Get a type of a floating point value with the specified width
/// \returns type info object
/// \param width width of the desired type

tinfo_t hexapi get_float_type(int width);


/// Create a type info by width and sign.
/// Returns a simple type (examples: int, short) with the given width and sign.
/// \param srcwidth size of the type in bytes
/// \param sign sign of the type

tinfo_t hexapi get_int_type_by_width_and_sign(int srcwidth, type_sign_t sign);


/// Create a partial type info by width.
/// Returns a partially defined type (examples: _DWORD, _BYTE) with the given width.
/// \param size size of the type in bytes

tinfo_t hexapi get_unk_type(int size);


/// Generate a dummy pointer type
///  \param ptrsize size of pointed object
///  \param isfp is floating point object?

tinfo_t hexapi dummy_ptrtype(int ptrsize, bool isfp);


/// Get type of a structure field.
/// This function performs validity checks of the field type. Wrong types are rejected.
/// \param mptr structure field
/// \param type pointer to the variable where the type is returned. This parameter can be NULL.
/// \param fields pointer to the variable where the fields are returned. This parameter can be NULL.
/// \return false if failed

bool hexapi get_member_type(const member_t *mptr, tinfo_t *type);


/// Create a pointer type.
/// This function performs the following conversion: "type" -> "type*"
/// \param type object type.
/// \return "type*". for example, if 'char' is passed as the argument,
//          the function will return 'char *'

tinfo_t hexapi make_pointer(const tinfo_t &type);


/// Create a reference to a named type.
/// \param name type name
/// \return type which refers to the specified name. For example, if name is "DWORD",
///             the type info which refers to "DWORD" is created.

tinfo_t hexapi create_typedef(const char *name);


/// Create a reference to an ordinal type.
/// \param n ordinal number of the type
/// \return type which refers to the specified ordianl. For example, if n is 1,
///             the type info which refers to ordinal type 1 is created.

inline tinfo_t create_typedef(int n)
{
  tinfo_t tif;
  tif.create_typedef(NULL, n);
  return tif;
}

/// Type source (where the type information comes from)
enum type_source_t
{
  GUESSED_NONE,  // not guessed, specified by the user
  GUESSED_WEAK,  // not guessed, comes from idb
  GUESSED_FUNC,  // guessed as a function
  GUESSED_DATA,  // guessed as a data item
  TS_NOELL  = 0x8000000, // can be used in set_type() to avoid merging into ellipsis
  TS_SHRINK = 0x4000000, // can be used in set_type() to prefer smaller arguments
  TS_MASK   = 0xC000000, // all high bits
};

inline int compare_typsrc(type_source_t s1, type_source_t s2)
{
  if ( s1 > GUESSED_WEAK && s2 > GUESSED_WEAK )
    return 0; // both guessed, consider equal
  return compare(s1, s2);
}


/// Get a global type.
/// Global types are types of addressable objects and struct/union/enum types
/// \param id address or id of the object
/// \param tif buffer for the answer
/// \param guess what kind of types to consider
/// \return success

bool hexapi get_type(uval_t id, tinfo_t *tif, type_source_t guess);


/// Set a global type.
/// \param id address or id of the object
/// \param tif new type info
/// \param guess where the type comes from
/// \param force true means to set the type as is, false means to merge the
///        new type with the possibly existing old type info.
/// \return success

bool hexapi set_type(uval_t id, const tinfo_t &tif, type_source_t source, bool force=false);


//-------------------------------------------------------------------------
// We use our own class to store argument and variable locations.
// The main differences between vdloc and argloc_t:
//   VLOC_REG1: the offset is always 0, so it is not used. the register number
//              uses the whole ~VLOC_MASK field.
//   VLOCK_STKOFF: stack offsets are always positive because they are based on
//              the lowest value of sp in the function.
class vdloc_t : public argloc_t
{
  int regoff(void); // inaccessible & undefined: regoff() should not be used
public:
  // use all available bits for register number for VLOC_REG1
  int reg1(void) const { return atype() == ALOC_REG2 ? argloc_t::reg1() : get_reginfo(); }
  void _set_reg1(int r1) { argloc_t::_set_reg1(r1, r1>>16); } // it works fine
  void set_reg1(int r1) { cleanup_argloc(this); _set_reg1(r1); }
  inline bool is_fpu_mreg() const;
};

size_t hexapi print_vdloc(char *buf, size_t bufsize, const vdloc_t &loc, int w);
//-------------------------------------------------------------------------
/// Do two arglocs overlap?
bool hexapi arglocs_overlap(const vdloc_t &loc1, size_t w1, const vdloc_t &loc2, size_t w2);

/// Local variable locator. Local variables are located using: definition ea, location
struct lvar_locator_t
{
  vdloc_t location;     ///< Variable location.
  ea_t defea;           ///< Definition address. The address of an instruction
                        ///< that initializes the variable. This value is
                        ///< assigned to each lvar by lvar allocator.
                        ///< BADADDR for function arguments
  lvar_locator_t(void) : defea(BADADDR) {}
  lvar_locator_t(const vdloc_t &loc, ea_t ea) : location(loc), defea(ea) {}
  /// Calculate the variable location (only for continuous variables)
  /// \return if the variable is register-hosted, the register number
  ///         otherwise, return the virtual stack register number that
  ///         corresponds to the stack location
  sval_t hexapi get_regnum(void) const;
  /// Is variable located on one register?
  bool is_reg1(void) const { return  location.is_reg1(); }
  /// Is variable located on two registers?
  bool is_reg2(void) const { return  location.is_reg2(); }
  /// Is variable located on register(s)?
  bool is_reg_var(void) const { return location.is_reg(); }
  /// Is variable located on the stack?
  bool is_stk_var(void) const { return location.is_stkoff(); }
  /// Is variable scattered?
  bool is_scattered(void) const { return location.is_scattered(); }
  /// Get number of the register for the variable
  mreg_t get_reg1(void) const { return location.reg1(); }
  /// Get number of the second register (only for tworeg lvars)
  mreg_t get_reg2(void) const { return location.reg2(); }
  /// Get information about scattered variable
  const scattered_aloc_t &get_scattered(void) const { return location.scattered(); }
        scattered_aloc_t &get_scattered(void)       { return location.scattered(); }
  DECLARE_COMPARISONS(lvar_locator_t);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

/// Definition of a local variable (register or stack) #var #lvar
class lvar_t : public lvar_locator_t
{
  friend class mbl_array_t;
  int flags;                    ///< \ref CVAR_
/// \defgroup CVAR_ Local variable property bits
/// Used in lvar_t::flags
//@{
#define CVAR_USED    0x0001     ///< is used in the code?
#define CVAR_TYPE    0x0002     ///< the type is defined?
#define CVAR_NAME    0x0004     ///< has nice name?
#define CVAR_MREG    0x0008     ///< corresponding mregs were replaced?
#define CVAR_NOWD    0x0010     ///< width is unknown
#define CVAR_UNAME   0x0020     ///< user-defined name
#define CVAR_UTYPE   0x0040     ///< user-defined type
#define CVAR_RESULT  0x0080     ///< function result variable
#define CVAR_ARG     0x0100     ///< function argument
#define CVAR_FAKE    0x0200     ///< fake return variable
#define CVAR_OVER    0x0400     ///< overlapping variable
#define CVAR_FLOAT   0x0800     ///< used in a fpu insn
#define CVAR_SPOILED 0x1000     ///< internal flag, do not use: spoiled var
#define CVAR_MAPDST  0x2000     ///< other variables are mapped to this var
#define CVAR_PARTIAL 0x4000     ///< variable type is partialy defined
//@}

public:
  qstring name;          ///< variable name.
                         ///< use mbl_array_t::set_nice_lvar_name() and
                         ///< mbl_array_t::set_user_lvar_name() to modify it
  qstring cmt;           ///< variable comment string
  tinfo_t tif;           ///< variable type
  int width;             ///< variable size in bytes
  int defblk;            ///< first block defining the variable.
                         ///< 0 for args, -1 if unknown
  uint64 divisor;        ///< max known divisor of the variable

  lvar_t(void) : flags(CVAR_USED), width(0), defblk(-1), divisor(0) {}
  lvar_t(const qstring &n, const vdloc_t &l, ea_t e, const tinfo_t &t, int w, int db)
    : lvar_locator_t(l, e), flags(CVAR_USED), name(n), tif(t), width(w),
      defblk(db), divisor(0) {}
  lvar_t(mreg_t reg, int width, const tinfo_t &type, int nblock, ea_t defea);

  /// Is the variable used in the code?
  bool used(void)  const { return (flags & CVAR_USED) != 0; }
  /// Has the variable a type?
  bool typed(void) const { return (flags & CVAR_TYPE) != 0; }
  /// Have corresponding microregs been replaced by references to this variable?
  bool mreg_done(void) const { return (flags & CVAR_MREG) != 0; }
  /// Does the variable have a nice name?
  bool has_nice_name(void) const { return (flags & CVAR_NAME) != 0; }
  /// Do we know the width of the variable?
  bool is_unknown_width(void) const { return (flags & CVAR_NOWD) != 0; }
  /// Has any user-defined information?
  bool has_user_info(void) const { return (flags & (CVAR_UNAME|CVAR_UTYPE)) != 0 || !cmt.empty(); }
  /// Has user-defined name?
  bool has_user_name(void) const { return (flags & CVAR_UNAME) != 0; }
  /// Has user-defined type?
  bool has_user_type(void) const { return (flags & CVAR_UTYPE) != 0; }
  /// Is the function result?
  bool is_result_var(void) const { return (flags & CVAR_RESULT) != 0; }
  /// Is the function argument?
  bool is_arg_var(void) const { return (flags & CVAR_ARG) != 0; }
  /// Is the promoted function argument?
  bool is_promoted_arg(void) const;
  /// Is fake return variable?
  bool is_fake_var(void) const { return (flags & CVAR_FAKE) != 0; }
  /// Is overlapped variable?
  bool is_overlapped_var(void) const { return (flags & CVAR_OVER) != 0; }
  /// Used by a fpu insn?
  bool is_floating_var(void) const { return (flags & CVAR_FLOAT) != 0; }
  /// Is spoiled var? (meaningful only during lvar allocation)
  bool is_spoiled_var(void) const { return (flags & CVAR_SPOILED) != 0; }
  /// Other variable(s) map to this var?
  bool is_partialy_typed(void) const { return (flags & CVAR_PARTIAL) != 0; }
  /// Other variable(s) map to this var?
  bool is_mapdst_var(void) const { return (flags & CVAR_MAPDST) != 0; }
  void set_used(void) { flags |= CVAR_USED; }
  void clear_used(void) { flags &= ~CVAR_USED; }
  void set_typed(void) { flags |= CVAR_TYPE; }
  void set_non_typed(void) { flags &= ~CVAR_TYPE; }
  void clr_user_info(void) { flags &= ~(CVAR_UNAME|CVAR_UTYPE); }
  void set_user_name(void) { flags |= CVAR_NAME|CVAR_UNAME; }
  void set_user_type(void) { flags |= CVAR_TYPE|CVAR_UTYPE; }
  void clr_user_type(void) { flags &= ~CVAR_UTYPE; }
  void clr_user_name(void) { flags &= ~CVAR_UNAME; }
  void set_mreg_done(void) { flags |= CVAR_MREG; }
  void clr_mreg_done(void) { flags &= ~CVAR_MREG; }
  void set_unknown_width(void) { flags |= CVAR_NOWD; }
  void clr_unknown_width(void) { flags &= ~CVAR_NOWD; }
  void set_arg_var(void) { flags |= CVAR_ARG; }
  void clr_arg_var(void) { flags &= ~CVAR_ARG; }
  void set_fake_var(void) { flags |= CVAR_FAKE; }
  void clr_fake_var(void) { flags &= ~CVAR_FAKE; }
  void set_overlapped_var(void) { flags |= CVAR_OVER; }
  void clr_overlapped_var(void) { flags &= ~CVAR_OVER; }
  void set_floating_var(void) { flags |= CVAR_FLOAT; }
  void clr_floating_var(void) { flags &= ~CVAR_FLOAT; }
  void set_spoiled_var(void) { flags |= CVAR_SPOILED; }
  void clr_spoiled_var(void) { flags &= ~CVAR_SPOILED; }
  void set_mapdst_var(void) { flags |= CVAR_MAPDST; }
  void clr_mapdst_var(void) { flags &= ~CVAR_MAPDST; }
  void set_partialy_typed(void) { flags |= CVAR_PARTIAL; }
  void clr_partialy_typed(void) { flags &= ~CVAR_PARTIAL; }

  void set_reg_name(const char *n)
  {
    name = n;              // do not verify uniqueness
    flags &= ~CVAR_USED;   // do not display the declaration
    flags |= CVAR_NAME;    // do not autorename
  }
  /// Do variables overlap?
  bool has_common(const lvar_t &v) const
  {
    return arglocs_overlap(location, width, v.location, v.width);
  }
  /// Does the variable overlap with the specified location?
  bool has_common_bit(const vdloc_t &loc, asize_t width2) const
  {
    return arglocs_overlap(location, width, loc, width2);
  }
  /// Get variable type
  const tinfo_t &type(void) const { return tif; }
  tinfo_t &type(void) { return tif; }

  /// Check if the variable accept the specified type.
  /// Some types are forbidden (void, function types, wrong arrays, etc)
  bool hexapi accepts_type(const tinfo_t &t);

  /// Set variable type without any validation.
  void force_lvar_type(const tinfo_t &t);

  /// Set variable type
  /// \param t new type
  /// \param may_fail if false and type is bad, interr
  /// \return success
  bool hexapi set_lvar_type(const tinfo_t &t, bool may_fail=false);

  /// Set final variable type.
  void set_final_lvar_type(const tinfo_t &t)
  {
    set_lvar_type(t);
    set_typed();
  }

  /// Change the variable width. This function also changes
  /// the variable type.
  /// \param w new width
  /// \param svw_flags combination of SVW_... bits
  /// \return success
  bool hexapi set_width(int w, int svw_flags=0);
#define SVW_INT   0x00 // integer value
#define SVW_FLOAT 0x01 // floating point value
#define SVW_SOFT  0x02 // may fail and return false;
                       // if this bit is not set and the type is bad, interr

};
DECLARE_TYPE_AS_MOVABLE(lvar_t);

/// Set of local variables
struct lvars_t : public qvector<lvar_t>
{
  /// Find input variable at the specified location.
  /// \param argloc variable location
  /// \param size variable size
  /// \return -1 if failed, otherwise the index into the variables vector.
  int find_input_lvar(const vdloc_t &argloc, int _size) { return find_lvar(argloc, _size, 0); }

  /// Find stack variable at the specified location.
  /// \param spoff offset from the minimal sp
  /// \param width variable size
  /// \return -1 if failed, otherwise the index into the variables vector.
  int hexapi find_stkvar(int32 spoff, int width);

  /// Find variable at the specified location.
  /// \param ll variable location
  /// \return pointer to variable or NULL
  lvar_t *hexapi find(const lvar_locator_t &ll);


  /// Find variable at the specified location.
  /// \param location variable location
  /// \param width variable size
  /// \param defblk definition block of the lvar. -1 means any block
  /// \return -1 if failed, otherwise the index into the variables vector.
  int hexapi find_lvar(const vdloc_t &location, int width, int defblk=-1);
};

/// Saved user settings for local variables: name, type, comment
struct lvar_saved_info_t
{
  lvar_locator_t ll;
  qstring name;
  tinfo_t type;
  qstring cmt;
  int flags;                    ///< \ref LVINF_
/// \defgroup LVINF_ saved user lvar info property bits
/// Used in lvar_saved_info_t::flags
//@{
#define LVINF_KEEP   0x0001     ///< keep saved user settings regardless of vars
//@}
  lvar_saved_info_t(void) : flags(0) {}
  bool has_info(void) const { return !name.empty() || !type.empty() || !cmt.empty(); }
  bool operator==(const lvar_saved_info_t &r) const
  {
    return name == r.name
        && cmt == r.cmt
        && ll == r.ll
        && type == r.type;
  }
  bool operator!=(const lvar_saved_info_t &r) const { return !(*this == r); }
  bool is_kept(void) const { return (flags & LVINF_KEEP) != 0; }
  void clear_keep(void) { flags &= ~LVINF_KEEP; }
  void set_keep(void) { flags |= LVINF_KEEP; }
};
DECLARE_TYPE_AS_MOVABLE(lvar_saved_info_t);
typedef qvector<lvar_saved_info_t> lvar_saved_infos_t;

/// Local variable mapping (is used to merge variables)
typedef std::map<lvar_locator_t, lvar_locator_t> lvar_mapping_t;

/// All user-defined information about local variables
struct lvar_uservec_t
{
  /// User-specified names, types, comments for lvars. Variables without
  /// user-specified info are not present in this vector.
  lvar_saved_infos_t lvvec;

  /// Parallel to lvvec array of variable sizes
  intvec_t sizes;

  /// Local variable mapping (used for merging variables)
  lvar_mapping_t lmaps;

  /// Delta to add to IDA stack offset to calculate Hex-Rays stack offsets.
  /// Should be set by the caller before calling save_user_lvar_settings();
  uval_t stkoff_delta;

  /// Various flags. Possible values are from \ref ULV_
  int ulv_flags;
/// \defgroup ULV_ lvar_uservec_t property bits
/// Used in lvar_uservec_t::ulv_flags
//@{
#define ULV_PRECISE_DEFEA 0x0001        ///< Use precise defea's for lvar locations
//@}

  lvar_uservec_t(void) : stkoff_delta(0), ulv_flags(ULV_PRECISE_DEFEA) {}
  void swap(lvar_uservec_t &r)
  {
    lvvec.swap(r.lvvec);
    sizes.swap(r.sizes);
    lmaps.swap(r.lmaps);
    std::swap(stkoff_delta, r.stkoff_delta);
    std::swap(ulv_flags, r.ulv_flags);
  }

  /// find saved user settings for given var
  lvar_saved_info_t *find_info(const lvar_locator_t &vloc)
  {
    for ( lvar_saved_infos_t::iterator p=lvvec.begin(); p != lvvec.end(); ++p )
    {
      if ( p->ll == vloc )
        return p;
    }
    return NULL;
  }

  /// keep user settings for given var
  void keep_info(const lvar_t &v)
  {
    lvar_saved_info_t *p = find_info(v);
    if ( p != NULL )
      p->set_keep();
  }
};

/// Restore user defined local variable settings in the database.
/// \param func_ea entry address of the function
/// \param lvinf ptr to output buffer
/// \return success

bool hexapi restore_user_lvar_settings(lvar_uservec_t *lvinf, ea_t func_ea);


/// Save user defined local variable settings into the database.
/// \param func_ea entry address of the function
/// \param lvinf user-specified info about local variables

void hexapi save_user_lvar_settings(ea_t func_ea, const lvar_uservec_t &lvinf);


/// Helper class to modify saved local variable settings.
struct user_lvar_modifier_t
{
  /// Modify lvar settings.
  /// Returns: true-modified
  virtual bool idaapi modify_lvars(lvar_uservec_t *lvinf) = 0;
};

/// Modify saved local variable settings.
///     \param entry_ea         function start address
///     \param mlv              local variable modifier
/// \return true if modified variables

bool hexapi modify_user_lvars(ea_t entry_ea, user_lvar_modifier_t &mlv);


//-------------------------------------------------------------------------
/// User-defined function calls
struct udcall_t
{
  qstring name;         // name of the function
  tinfo_t tif;          // function prototype
};

// All user-defined function calls (map address -> udcall)
typedef std::map<ea_t, udcall_t> udcall_map_t;

/// Restore user defined function calls from the database.
/// \param udcalls ptr to output buffer
/// \param func_ea entry address of the function
/// \return success

bool hexapi restore_user_defined_calls(udcall_map_t *udcalls, ea_t func_ea);

/// Save user defined local function calls into the database.
/// \param func_ea entry address of the function
/// \param udcalls user-specified info about user defined function calls

void hexapi save_user_defined_calls(ea_t func_ea, const udcall_map_t &udcalls);

/// Convert function type declaration into internal structure
/// \param udc    - pointer to output structure
/// \param decl   - function type declaration
/// \param silent - if TRUE: do not show warning in case of incorrect type
/// \return success
bool hexapi parse_user_call(udcall_t *udc, const char *decl, bool silent);

/// try to generate user-defined call for an instruction
/// \return MERR_... code:
///   MERR_OK      - user-defined call generated
///   else         - error (MERR_INSN == inacceptable udc.tif)
int hexapi convert_to_user_call(const udcall_t &udc, codegen_t &cdg);

//-------------------------------------------------------------------------
/// Generic microcode generator class.
/// An instance of a derived class can be registered to be used for
/// non-standard microcode generation. Before microcode generation for an
/// instruction all registered object will be visited by the following way:
///   if ( filter->match(cdg) )
///     code = filter->apply(cdg);
///   if ( code == MERR_OK )
///     continue;     // filter generated microcode, go to the next instruction
struct microcode_filter_t
{
  /// check if the filter object is to be appied
  /// \return success
  virtual bool match(codegen_t &cdg) = 0;
  /// generate microcode for an instruction
  /// \return MERR_... code:
  ///   MERR_OK      - user-defined call generated, go to the next instruction
  ///   MERR_INSN    - not generated - the caller should try the standard way
  ///   else         - error
  virtual int apply(codegen_t &cdg) = 0;
};

/// register/unregister non-standard microcode generator
/// \param filter  - microcode generator object
/// \param install - TRUE - register the object, FALSE - unregister
void hexapi install_microcode_filter(microcode_filter_t *filter, bool install=true);

//-------------------------------------------------------------------------
/// Abstract class: User-defined call generator
/// derived classes should implement method 'match'
class udc_filter_t : public microcode_filter_t
{
  udcall_t udc;

public:
  /// return true if the filter object should be appied to given instruction
  virtual bool match(codegen_t &cdg) = 0;

  bool hexapi init(const char *decl);
  virtual int hexapi apply(codegen_t &cdg);
};

//-------------------------------------------------------------------------
struct fnumber_t        /// Floating point constant.
                        /// For more details, please see the ieee.h file from IDA SDK.
{
  uint16 fnum[6];       ///< Internal representation of the number
  int nbytes;           ///< Original size of the constant in bytes
  operator       uint16 *(void)       { return fnum; }
  operator const uint16 *(void) const { return fnum; }
  size_t hexapi print(char *buf, size_t bufsize) const;
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(fnumber_t)
  {
    return ecmp(fnum, r.fnum);
  }
};

//-------------------------------------------------------------------------
// Warning ids
enum warnid_t
{
  WARN_VARARG_REGS,   //  0 can not handle register arguments in vararg function, discarded them
  WARN_ILL_PURGED,    //  1 odd caller purged bytes %d, correcting
  WARN_ILL_FUNCTYPE,  //  2 invalid function type has been ignored
  WARN_VARARG_TCAL,   //  3 can not handle tail call to vararg
  WARN_VARARG_NOSTK,  //  4 call vararg without local stack
  WARN_VARARG_MANY,   //  5 too many varargs, some ignored
  WARN_ADDR_OUTARGS,  //  6 can not handle address arithmetics in outgoing argument area of stack frame -- unused
  WARN_DEP_UNK_CALLS, //  7 found interdependent unknown calls
  WARN_ILL_ELLIPSIS,  //  8 erroneously detected ellipsis type has been ignored
  WARN_GUESSED_TYPE,  //  9 using guessed type %s;
  WARN_EXP_LINVAR,    // 10 failed to expand a linear variable
  WARN_WIDEN_CHAINS,  // 11 failed to widen chains
  WARN_BAD_PURGED,    // 12 inconsistent function type and number of purged bytes
  WARN_CBUILD_LOOPS,  // 13 too many cbuild loops
  WARN_NO_SAVE_REST,  // 14 could not find valid save-restore pair for %s
  WARN_ODD_INPUT_REG, // 15 odd input register %s
  WARN_ODD_ADDR_USE,  // 16 odd use of a variable address
  WARN_MUST_RET_FP,   // 17 function return type is incorrect (must be floating point)
  WARN_ILL_FPU_STACK, // 18 inconsistent fpu stack
  WARN_SELFREF_PROP,  // 19 self-referencing variable has been detected
  WARN_WOULD_OVERLAP, // 20 variables would overlap: %s
  WARN_ARRAY_INARG,   // 21 array has been used for an input argument
  WARN_MAX_ARGS,      // 22 too many input arguments, some ignored
  WARN_BAD_FIELD_TYPE,// 23 incorrect structure member type for %s::%s, ignored
  WARN_WRITE_CONST,   // 24 write access to const memory at %a has been detected
  WARN_BAD_RETVAR,    // 25 wrong return variable
  WARN_FRAG_LVAR,     // 26 fragmented variable at %s may be wrong
  WARN_HUGE_STKOFF,   // 27 exceedingly huge offset into the stack frame
  WARN_UNINITED_REG,  // 28 reference to an uninitialized register has been removed: %s
  WARN_FIXED_MACRO,   // 29 fixed broken macro-insn
  WARN_WRONG_VA_OFF,  // 30 wrong offset of va_list variable
  WARN_CR_NOFIELD,    // 31 CONTAINING_RECORD: no field '%s' in struct '%s' at %d
  WARN_CR_BADOFF,     // 32 CONTAINING_RECORD: too small offset %d for struct '%s'
  WARN_BAD_STROFF,    // 33 user specified stroff has not been processed: %s
  WARN_BAD_VARSIZE,   // 34 inconsistent variable size for '%s'
  WARN_UNSUPP_REG,    // 35 unsupported processor register '%s'
  WARN_UNALIGNED_ARG, // 36 unaligned function argument '%s'

  WARN_MAX,
};

// Warnings
struct hexwarn_t
{
  ea_t ea;
  warnid_t id;
  qstring text;
  DECLARE_COMPARISONS(hexwarn_t)
  {
    if ( ea < r.ea )
      return -1;
    if ( ea > r.ea )
      return 1;
    if ( id < r.id )
      return -1;
    if ( id > r.id )
      return 1;
    return strcmp(text.c_str(), r.text.c_str());
  }
};
DECLARE_TYPE_AS_MOVABLE(hexwarn_t);
typedef qvector<hexwarn_t> hexwarns_t;

//-------------------------------------------------------------------------
// helper class to generate the initial microcode
class codegen_t
{
public:
  mbl_array_t *mba;
  mblock_t *mb;
  insn_t insn;
  char ignore_micro;

  codegen_t(mbl_array_t *m)
    : mba(m), mb(NULL), ignore_micro(IM_NONE) {}
  virtual ~codegen_t(void)
  {
  }

  // Analyze prolog/epilog of the function to decompile
  // If found, allocate and fill 'mba->pi' structure.
  virtual int idaapi analyze_prolog(
        const class qflow_chart_t &fc,
        const class bitset_t &reachable) = 0;

  // Generate microcode for one instruction
  virtual int idaapi gen_micro() = 0;

  // Generate microcode to load one operand
  virtual mreg_t idaapi load_operand(int opnum) = 0;
}; //-

//-------------------------------------------------------------------------
/// Get decompiler version.
/// The returned string is of the form <major>.<minor>.<revision>.<build-date>
/// \return pointer to version string. For example: "2.0.0.140605"

const char *hexapi get_hexrays_version(void);


/// Open pseudocode window.
/// The specified function is decompiled and the pseudocode window is opened.
/// \param ea function to decompile
/// \param new_window 0:reuse existing window; 1:open new window;
///        -1: reuse existing window if the current view is pseudocode
/// \return false if failed

vdui_t *hexapi open_pseudocode(ea_t ea, int new_window);


/// Close pseudocode window.
/// \param f pointer to window
/// \return false if failed

bool hexapi close_pseudocode(TWidget *f);


/// Get the vdui_t instance associated to the TWidget
/// \param f pointer to window
/// \return a vdui_t *, or NULL

vdui_t *hexapi get_widget_vdui(TWidget *f);


/// \defgroup VDRUN_ Batch decompilation bits
//@{
#define VDRUN_NEWFILE 0x0000  ///< Create a new file or overwrite existing file
#define VDRUN_APPEND  0x0001  ///< Create a new file or append to existing file
#define VDRUN_ONLYNEW 0x0002  ///< Fail if output file already exists
#define VDRUN_SILENT  0x0004  ///< Silent decompilation
#define VDRUN_SENDIDB 0x0008  ///< Send problematic databases to hex-rays.com
#define VDRUN_MAYSTOP 0x0010  ///< the user can cancel decompilation
#define VDRUN_CMDLINE 0x0020  ///< called from ida's command line
#define VDRUN_STATS   0x0040  ///< print statistics into vd_stats.txt
//@}

/// Batch decompilation.
/// Decompile all or the specified functions
/// \return true if no internal error occured and the user has not cancelled decompilation
/// \param outfile name of the output file
/// \param funcaddrs list of functions to decompile.
///                  If NULL or empty, then decompile all nonlib functions
/// \param flags \ref VDRUN_

bool hexapi decompile_many(const char *outfile, eavec_t *funcaddrs, int flags);


/// Get textual description of an error code
/// \return pointer to static error description string
/// \param code \ref MERR_

const char *hexapi micro_err_format(int code);

/// \defgroup MERR_ Microcode error codes
//@{
#define MERR_OK        0       ///< ok
#define MERR_BLOCK     1       ///< no error, switch to new block
#define MERR_INTERR    (-1)    ///< internal error
#define MERR_INSN      (-2)    ///< can not convert to microcode
#define MERR_MEM       (-3)    ///< not enough memory
#define MERR_BADBLK    (-4)    ///< bad block found
#define MERR_BADSP     (-5)    ///< positive sp value has been found
#define MERR_PROLOG    (-6)    ///< prolog analysis failed
#define MERR_SWITCH    (-7)    ///< wrong switch idiom
#define MERR_EXCEPTION (-8)    ///< exception analysis failed
#define MERR_HUGESTACK (-9)    ///< stack frame is too big
#define MERR_LVARS     (-10)   ///< local variable allocation failed
#define MERR_BITNESS   (-11)   ///< only 32/16bit functions can be decompiled
#define MERR_BADCALL   (-12)   ///< could not determine call arguments
#define MERR_BADFRAME  (-13)   ///< function frame is wrong
#define MERR_UNKTYPE   (-14)   ///< undefined type %s (currently unused error code)
#define MERR_BADIDB    (-15)   ///< inconsistent database information
#define MERR_SIZEOF    (-16)   ///< wrong basic type sizes in compiler settings
#define MERR_REDO      (-17)   ///< redecompilation has been requested
#define MERR_CANCELED  (-18)   ///< decompilation has been cancelled
#define MERR_RECDEPTH  (-19)   ///< max recursion depth reached during lvar allocation
#define MERR_OVERLAP   (-20)   ///< variables would overlap: %s
#define MERR_PARTINIT  (-21)   ///< partially initialized variable %s
#define MERR_COMPLEX   (-22)   ///< too complex function
#define MERR_LICENSE   (-23)   ///< no license available
#define MERR_ONLY32    (-24)   ///< only 32-bit functions can be decompiled for the current database
#define MERR_ONLY64    (-25)   ///< only 64-bit functions can be decompiled for the current database
#define MERR_BUSY      (-26)   ///< already decompiling a function
#define MERR_FARPTR    (-27)   ///< far memory model is supported only for pc
#define MERR_EXTERN    (-28)   ///< special segments can not be decompiled
#define MERR_FUNCSIZE  (-29)   ///< too big function
#define MERR_MAX_ERR   29
#define MERR_LOOP      (-30)   ///< internal code: redo last loop (never reported)
//@}

/// Exception object: decompiler failure information
struct hexrays_failure_t
{
  int code;                     ///< \ref MERR_
  ea_t errea;                   ///< associated address
  qstring str;                  ///< string information
  hexrays_failure_t(void) : code(MERR_OK), errea(BADADDR) {}
  hexrays_failure_t(int c, ea_t ea, const char *buf=NULL) : code(c), errea(ea), str(buf) {}
  hexrays_failure_t(int c, ea_t ea, const qstring &buf) : code(c), errea(ea), str(buf) {}
  qstring hexapi desc(void) const;
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

/// Exception object: decompiler exception
struct vd_failure_t : public std::exception
{
  hexrays_failure_t hf;
  vd_failure_t(void) {}
  vd_failure_t(int code, ea_t ea, const char *buf=NULL) : hf(code, ea, buf) {}
  vd_failure_t(int code, ea_t ea, const qstring &buf) : hf(code, ea, buf) {}
  vd_failure_t(const hexrays_failure_t &_hf) : hf(_hf) {}
  qstring desc(void) const { return hf.desc(); }
#ifdef __GNUC__
  ~vd_failure_t(void) throw() {}
#endif
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

/// Exception object: decompiler internal error
struct vd_interr_t : public vd_failure_t
{
  vd_interr_t(ea_t ea, const qstring &buf) : vd_failure_t(MERR_INTERR, ea, buf) {}
  vd_interr_t(ea_t ea, const char *buf) : vd_failure_t(MERR_INTERR, ea, buf) {}
};

/// Send the database to Hex-Rays.
/// This function sends the current database to the hex-rays server.
/// The database is sent in the compressed form over an encrypted (SSL) connection.
/// \param err failure description object. Empty hexrays_failure_t object can be used if error information is not available.
/// \param silent if false, a dialog box will be displayed before sending the database.

void hexapi send_database(const hexrays_failure_t &err, bool silent);

//-------------------------------------------------------------------------
/// Ctree element type. At the beginning of this list there are expression
/// elements (cot_...), followed by statement elements (cit_...).
enum ctype_t
{
  cot_empty    = 0,
  cot_comma    = 1,   ///< x, y
  cot_asg      = 2,   ///< x = y
  cot_asgbor   = 3,   ///< x |= y
  cot_asgxor   = 4,   ///< x ^= y
  cot_asgband  = 5,   ///< x &= y
  cot_asgadd   = 6,   ///< x += y
  cot_asgsub   = 7,   ///< x -= y
  cot_asgmul   = 8,   ///< x *= y
  cot_asgsshr  = 9,   ///< x >>= y signed
  cot_asgushr  = 10,  ///< x >>= y unsigned
  cot_asgshl   = 11,  ///< x <<= y
  cot_asgsdiv  = 12,  ///< x /= y signed
  cot_asgudiv  = 13,  ///< x /= y unsigned
  cot_asgsmod  = 14,  ///< x %= y signed
  cot_asgumod  = 15,  ///< x %= y unsigned
  cot_tern     = 16,  ///< x ? y : z
  cot_lor      = 17,  ///< x || y
  cot_land     = 18,  ///< x && y
  cot_bor      = 19,  ///< x | y
  cot_xor      = 20,  ///< x ^ y
  cot_band     = 21,  ///< x & y
  cot_eq       = 22,  ///< x == y int or fpu (see EXFL_FPOP)
  cot_ne       = 23,  ///< x != y int or fpu (see EXFL_FPOP)
  cot_sge      = 24,  ///< x >= y signed or fpu (see EXFL_FPOP)
  cot_uge      = 25,  ///< x >= y unsigned
  cot_sle      = 26,  ///< x <= y signed or fpu (see EXFL_FPOP)
  cot_ule      = 27,  ///< x <= y unsigned
  cot_sgt      = 28,  ///< x >  y signed or fpu (see EXFL_FPOP)
  cot_ugt      = 29,  ///< x >  y unsigned
  cot_slt      = 30,  ///< x <  y signed or fpu (see EXFL_FPOP)
  cot_ult      = 31,  ///< x <  y unsigned
  cot_sshr     = 32,  ///< x >> y signed
  cot_ushr     = 33,  ///< x >> y unsigned
  cot_shl      = 34,  ///< x << y
  cot_add      = 35,  ///< x + y
  cot_sub      = 36,  ///< x - y
  cot_mul      = 37,  ///< x * y
  cot_sdiv     = 38,  ///< x / y signed
  cot_udiv     = 39,  ///< x / y unsigned
  cot_smod     = 40,  ///< x % y signed
  cot_umod     = 41,  ///< x % y unsigned
  cot_fadd     = 42,  ///< x + y fp
  cot_fsub     = 43,  ///< x - y fp
  cot_fmul     = 44,  ///< x * y fp
  cot_fdiv     = 45,  ///< x / y fp
  cot_fneg     = 46,  ///< -x fp
  cot_neg      = 47,  ///< -x
  cot_cast     = 48,  ///< (type)x
  cot_lnot     = 49,  ///< !x
  cot_bnot     = 50,  ///< ~x
  cot_ptr      = 51,  ///< *x, access size in 'ptrsize'
  cot_ref      = 52,  ///< &x
  cot_postinc  = 53,  ///< x++
  cot_postdec  = 54,  ///< x--
  cot_preinc   = 55,  ///< ++x
  cot_predec   = 56,  ///< --x
  cot_call     = 57,  ///< x(...)
  cot_idx      = 58,  ///< x[y]
  cot_memref   = 59,  ///< x.m
  cot_memptr   = 60,  ///< x->m, access size in 'ptrsize'
  cot_num      = 61,  ///< n
  cot_fnum     = 62,  ///< fpc
  cot_str      = 63,  ///< string constant
  cot_obj      = 64,  ///< obj_ea
  cot_var      = 65,  ///< v
  cot_insn     = 66,  ///< instruction in expression, internal representation only
  cot_sizeof   = 67,  ///< sizeof(x)
  cot_helper   = 68,  ///< arbitrary name
  cot_type     = 69,  ///< arbitrary type
  cot_last     = cot_type,
  cit_empty    = 70,  ///< instruction types start here
  cit_block    = 71,  ///< block-statement: { ... }
  cit_expr     = 72,  ///< expression-statement: expr;
  cit_if       = 73,  ///< if-statement
  cit_for      = 74,  ///< for-statement
  cit_while    = 75,  ///< while-statement
  cit_do       = 76,  ///< do-statement
  cit_switch   = 77,  ///< switch-statement
  cit_break    = 78,  ///< break-statement
  cit_continue = 79,  ///< continue-statement
  cit_return   = 80,  ///< return-statement
  cit_goto     = 81,  ///< goto-statement
  cit_asm      = 82,  ///< asm-statement
  cit_end
};

/// \defgroup fixtype_t C operator writing styles
/// Used in operator_info_t::fixtype
//@{
const uchar
  FX_NONE    = 0,       ///< not applicable
  FX_INFIX   = 1,       ///< infix: a + b
  FX_PREFIX  = 2,       ///< prefix: *a
  FX_POSTFIX = 3,       ///< postfix: a++
  FX_TERNARY = 4;       ///< ternary: a ? b : c
//@}

/// \defgroup opattrs_t C operator attributes
/// Used in operator_info_t::flags
//@{
const uchar
  COI_RL     = 0x00,    ///< right to left
  COI_LR     = 0x01,    ///< left to right
  COI_INT    = 0x02,    ///< requires integer operands
  COI_FP     = 0x04,    ///< requires floating point operands
  COI_SH     = 0x08,    ///< is shift operation?
  COI_SGN    = 0x10,    ///< sign sensitive?
  COI_SBN    = 0x20;    ///< is simple binary?
//@}

/// Information about C operator
struct operator_info_t
{
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  const char *text;     ///< Text representation
  uchar precedence;     ///< Operator precedence (lower: more priority)
  uchar valency;        ///< Number of operator arguments
  uchar fixtype;        ///< \ref fixtype_t
  uchar flags;          ///< \ref opattrs_t
};



/// Negate a comparison operator. For example, \ref cot_sge becomes \ref cot_slt
ctype_t hexapi negated_relation(ctype_t op);
/// Get operator sign. Meaningful for sign-dependent operators, like \ref cot_sdiv
type_sign_t hexapi get_op_signness(ctype_t op);
/// Convert plain operator into assignment operator. For example, \ref cot_add returns \ref cot_asgadd
ctype_t hexapi asgop(ctype_t cop);
/// Convert assignment operator into plain operator. For example, \ref cot_asgadd returns \ref cot_add
/// \return cot_empty is the input operator is not an assignment operator.
ctype_t hexapi asgop_revert(ctype_t cop);
/// Does operator use the 'x' field of cexpr_t?
inline bool op_uses_x(ctype_t op) { return op >= cot_comma && op <= cot_memptr; }
/// Does operator use the 'y' field of cexpr_t?
inline bool op_uses_y(ctype_t op) { return (op >= cot_comma && op <= cot_fdiv) || op == cot_idx; }
/// Does operator use the 'z' field of cexpr_t?
inline bool op_uses_z(ctype_t op) { return op == cot_tern; }
/// Is binary operator?
inline bool is_binary(ctype_t op) { return op_uses_y(op) && op != cot_tern; } // x,y
/// Is unary operator?
inline bool is_unary(ctype_t op) { return op >= cot_fneg && op <= cot_predec; }
/// Is comparison operator?
inline bool is_relational(ctype_t op) { return op >= cot_eq && op <= cot_ult; }
/// Is assignment operator?
inline bool is_assignment(ctype_t op) { return op >= cot_asg && op <= cot_asgumod; }
// Can operate on UDTs?
inline bool accepts_udts(ctype_t op) { return op == cot_asg || op == cot_comma || op > cot_last; }
/// Is pre/post increment/decrement operator?
inline bool is_prepost(ctype_t op)    { return op >= cot_postinc && op <= cot_predec; }
/// Is commutative operator?
inline bool is_commutative(ctype_t op)
{
  return op == cot_bor
      || op == cot_xor
      || op == cot_band
      || op == cot_add
      || op == cot_mul
      || op == cot_fadd
      || op == cot_fmul
      || op == cot_ne
      || op == cot_eq;
}
/// Is additive operator?
inline bool is_additive(ctype_t op)
{
  return op == cot_add
      || op == cot_sub
      || op == cot_fadd
      || op == cot_fsub;
}
/// Is multiplicative operator?
inline bool is_multiplicative(ctype_t op)
{
  return op == cot_mul
      || op == cot_sdiv
      || op == cot_udiv
      || op == cot_fmul
      || op == cot_fdiv;
}

/// Is bit related operator?
inline bool is_bitop(ctype_t op)
{
  return op == cot_bor
      || op == cot_xor
      || op == cot_band
      || op == cot_bnot;
}

/// Is logical operator?
inline bool is_logical(ctype_t op)
{
  return op == cot_lor
      || op == cot_land
      || op == cot_lnot;
}

/// Is loop statement code?
inline bool is_loop(ctype_t op)
{
  return op == cit_for
      || op == cit_while
      || op == cit_do;
}
/// Does a break statement influence the specified statement code?
inline bool is_break_consumer(ctype_t op)
{
  return is_loop(op) || op == cit_switch;
}

/// Is Lvalue operator?
inline bool is_lvalue(ctype_t op)
{
  return op == cot_ptr      // *x
      || op == cot_idx      // x[y]
      || op == cot_memref   // x.m
      || op == cot_memptr   // x->m
      || op == cot_obj      // v
      || op == cot_var;     // l
}

/// Is the operator allowed on small struni (structure/union)?
inline bool is_allowed_on_small_struni(ctype_t op)
{
  return op == cit_return
      || op == cot_asg
      || op == cot_eq
      || op == cot_ne
      || op == cot_comma
      || op == cot_tern
      || (op > cot_last && op < cit_end); // any insn
}

/// An immediate number
struct cnumber_t
{
  uint64 _value;                ///< its value
  number_format_t nf;           ///< how to represent it
  cnumber_t(int _opnum=0) : _value(0), nf(_opnum) {}

  /// Get text representation
  /// \param buf output buffer
  /// \param bufsize size of output buffer
  /// \param type number type
  size_t hexapi print(char *buf, size_t bufsize, const tinfo_t &type, const citem_t *parent=NULL, bool *nice_stroff=NULL) const;

  /// Get value.
  /// This function will properly extend the number sign to 64bits
  /// depending on the type sign.
  uint64 hexapi value(const tinfo_t &type) const;

  /// Assign new value
  /// \param v new value
  /// \param nbytes size of the new value in bytes
  /// \param sign sign of the value
  void hexapi assign(uint64 v, int nbytes, type_sign_t sign);

  DECLARE_COMPARISONS(cnumber_t);
};

/// Reference to a local variable
struct var_ref_t
{
  mbl_array_t *mba;     ///< pointer to the underlying micro array
  int idx;              ///< index into lvars_t
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  DECLARE_COMPARISONS(var_ref_t);
};

/// Vector of parents
typedef qvector<citem_t *> ctree_items_t;
typedef ctree_items_t parents_t;

/// A generic helper class that is used for ctree traversal
struct ctree_visitor_t
{
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  int cv_flags;           ///< \ref CV_
/// \defgroup CV_ Ctree visitor property bits
/// Used in ctree_visitor_t::cv_flags
//@{
#define CV_FAST    0x0000 ///< do not maintain parent information
#define CV_PRUNE   0x0001 ///< this bit is set by visit...() to prune the walk
#define CV_PARENTS 0x0002 ///< maintain parent information
#define CV_POST    0x0004 ///< call the leave...() functions
#define CV_RESTART 0x0008 ///< restart enumeration at the top expr (apply_to_exprs)
#define CV_INSNS   0x0010 ///< visit only statements, prune all expressions
                          ///< do not use before the final ctree maturity because
                          ///< expressions may contain statements at intermediate
                          ///< stages (see cot_insn). Otherwise you risk missing
                          ///< statements embedded into expressions.
//@}
  /// Should the parent information by maintained?
  bool maintain_parents(void) const { return (cv_flags & CV_PARENTS) != 0; }
  /// Should the traversal skip the children of the current item?
  bool must_prune(void)       const { return (cv_flags & CV_PRUNE) != 0; }
  /// Should the traversal restart?
  bool must_restart(void)     const { return (cv_flags & CV_RESTART) != 0; }
  /// Should the leave...() functions be called?
  bool is_postorder(void)     const { return (cv_flags & CV_POST) != 0; }
  /// Should all expressions be automatically pruned?
  bool only_insns(void)       const { return (cv_flags & CV_INSNS) != 0; }
  /// Prune children.
  /// This function may be called by a visitor() to skip all children of the current item.
  void prune_now(void) { cv_flags |= CV_PRUNE; }
  /// Do not prune children. This is an internal function, no need to call it.
  void clr_prune(void) { cv_flags &= ~CV_PRUNE; }
  /// Restart the travesal. Meaningful only in apply_to_exprs()
  void set_restart(void) { cv_flags |= CV_RESTART; }
  /// Do not restart. This is an internal function, no need to call it.
  void clr_restart(void) { cv_flags &= ~CV_RESTART; }

  parents_t parents;      ///< Vector of parents of the current item

  /// Constructor.
  /// This constructor can be used with CV_FAST, CV_PARENTS
  /// combined with CV_POST, CV_ONLYINS
  ctree_visitor_t(int _flags) : cv_flags(_flags) {}

  DEFINE_VIRTUAL_DTOR(ctree_visitor_t);
  /// Traverse ctree.
  /// The traversal will start at the specified item and continue until
  /// of one the visit_...() functions return a non-zero value.
  /// \param item root of the ctree to traverse
  /// \param parent parent of the specified item. can be specified as NULL.
  /// \return 0 or a non-zero value returned by a visit_...() function
  int hexapi apply_to(citem_t *item, citem_t *parent);

  /// Traverse only expressions.
  /// The traversal will start at the specified item and continue until
  /// of one the visit_...() functions return a non-zero value.
  /// \param item root of the ctree to traverse
  /// \param parent parent of the specified item. can be specified as NULL.
  /// \return 0 or a non-zero value returned by a visit_...() function
  int hexapi apply_to_exprs(citem_t *item, citem_t *parent);

  /// Get parent of the current item as an expression
  cexpr_t *parent_expr(void) { return (cexpr_t *)parents.back(); }
  /// Get parent of the current item as a statement
  cinsn_t *parent_insn(void) { return (cinsn_t *)parents.back(); }

  // the following functions are redefined by the derived class
  // in order to perform the desired actions during the traversal

  /// Visit a statement.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs pre-order traserval, i.e. an item is visited before
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi visit_insn(cinsn_t *) { return 0; }

  /// Visit an expression.
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs pre-order traserval, i.e. an item is visited before
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi visit_expr(cexpr_t *) { return 0; }

  /// Visit a statement after having visited its children
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs post-order traserval, i.e. an item is visited after
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi leave_insn(cinsn_t *) { return 0; }

  /// Visit an expression after having visited its children
  /// This is a visitor function which should be overridden by a derived
  /// class to do some useful work.
  /// This visitor performs post-order traserval, i.e. an item is visited after
  /// its children.
  /// \return 0 to continue the traversal, nonzero to stop.
  virtual int idaapi leave_expr(cexpr_t *) { return 0; }
};

/// A helper ctree traversal class that maintains parent information
struct ctree_parentee_t : public ctree_visitor_t
{
  ctree_parentee_t(bool post=false)
    : ctree_visitor_t((post ? CV_POST : 0)|CV_PARENTS) {}

  /// Recalculate types of parent node.
  /// If a node type has been changed, the visitor must recalculate
  /// all parent types, otherwise the ctree becomes inconsistent.
  /// If during this recalculation a parent node is added/deleted,
  /// this function returns true. In this case it is recommended
  /// to restart the traversal because the information about parent nodes
  /// is stale.
  /// \return false-ok to continue the traversal, true-must stop.
  bool hexapi recalc_parent_types(void);
};

/// Class to traverse the whole function
struct cfunc_parentee_t : public ctree_parentee_t
{
  cfunc_t *func;        ///< Pointer to current function
  cfunc_parentee_t(cfunc_t *f, bool post=false)
    : ctree_parentee_t(post), func(f) {}

  /// Calculate rvalue type.
  /// This function tries to determine the type of the specified item
  /// based on its context. For example, if the current expression is the
  /// right side of an assignment operator, the type
  /// of its left side will be returned. This function can be used to determine the 'best'
  /// type of the specified expression.
  /// \param[in] e expression to determine the desired type
  /// \param[out] target 'best' type of the expression will be returned here
  /// \return false if failed
  bool hexapi calc_rvalue_type(tinfo_t *target, const cexpr_t *e);
};

/// Ctree maturity level. The level will increase
/// as we switch from one phase of ctree generation to the next one
enum ctree_maturity_t
{
  CMAT_ZERO,            ///< does not exist
  CMAT_BUILT,           ///< just generated
  CMAT_TRANS1,          ///< applied first wave of transformations
  CMAT_NICE,            ///< nicefied expressions
  CMAT_TRANS2,          ///< applied second wave of transformations
  CMAT_CPA,             ///< corrected pointer arithmetic
  CMAT_TRANS3,          ///< applied third wave of transformations
  CMAT_CASTED,          ///< added necessary casts
  CMAT_FINAL,           ///< ready-to-use
};

//--------------------------------------------------------------------------
/// Comment item preciser.
/// Item preciser is used to assign comments to ctree items
/// A ctree item may have several comments attached to it. For example,
/// an if-statement may have the following comments: <pre>
///  if ( ... )    // cmt1
///  {             // cmt2
///  }             // cmt3
///  else          // cmt4
///  {                     -- usually the else block has a separate ea
///  } </pre>
/// The first 4 comments will have the same ea. In order to denote the exact
/// line for the comment, we store the item_preciser along with ea.
enum item_preciser_t
{
  // inner comments (comments within an expression)
  ITP_EMPTY,    ///< nothing
  ITP_ARG1,     ///< , (64 entries are reserved for 64 call arguments)
  ITP_ARG64 = ITP_ARG1+63, // ,
  ITP_BRACE1,   // (
  ITP_INNER_LAST = ITP_BRACE1,
  // outer comments
  ITP_ASM,      ///< __asm-line
  ITP_ELSE,     ///< else-line
  ITP_DO,       ///< do-line
  ITP_SEMI,     ///< semicolon
  ITP_CURLY1,   ///< {
  ITP_CURLY2,   ///< }
  ITP_BRACE2,   ///< )
  ITP_COLON,    ///< : (label)
  ITP_BLOCK1,   ///< opening block comment. this comment is printed before the item
                ///< (other comments are indented and printed after the item)
  ITP_BLOCK2,   ///< closing block comment.
  ITP_CASE = 0x40000000, ///< bit for switch cases
  ITP_SIGN = 0x20000000, ///< if this bit is set too, then we have a negative case value
                         // this is a hack, we better introduce special indexes for case values
                         // case value >= ITP_CASE will be processed incorrectly
};
/// Ctree location. Used to denote comment locations.
struct treeloc_t
{
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  ea_t ea;
  item_preciser_t itp;
  bool operator < (const treeloc_t &r) const
  {
    return ea < r.ea
        || (ea == r.ea && itp < r.itp);
  }
  bool operator == (const treeloc_t &r) const
  {
    return ea == r.ea && itp == r.itp;
  }
};

/// Comment retrieval type.
/// Ctree remembers what comments have already been retrieved.
/// This is done because our mechanism of item_precisers is still
/// not perfect and in theory some listing lines can not be told
/// apart. To avoid comment duplication, we remember if a comment
/// has already been used or not.
enum cmt_retrieval_type_t
{
  RETRIEVE_ONCE,        ///< Retrieve comment if it has not been used yet
  RETRIEVE_ALWAYS,      ///< Retrieve comment even if it has been used
};

/// Ctree item comment.
/// For each comment we remember its body and the fact of its retrieval
struct citem_cmt_t : public qstring
{
  mutable bool used;    ///< the comment has been retrieved?
  citem_cmt_t(void) : used(false) {}
  citem_cmt_t(const char *s) : qstring(s), used(false) {}
};

// Comments are attached to tree locations:
typedef std::map<treeloc_t, citem_cmt_t> user_cmts_t;

/// Generic ctree element locator. It can be used for instructions and some expression
/// types. However, we need more precise locators for other items (e.g. for numbers)
struct citem_locator_t
{
  ea_t ea;              ///< citem address
  ctype_t op;           ///< citem operation
private:
  //forbid the default constructor
  citem_locator_t(void) {}
public:
  citem_locator_t(ea_t _ea, ctype_t _op) : ea(_ea), op(_op) {}
  citem_locator_t(const citem_t *i);
  DECLARE_COMPARISONS(citem_locator_t);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

// citem_t::iflags are attached to (ea,op) pairs
typedef std::map<citem_locator_t, int32> user_iflags_t;

// union field selections
// they are represented as a vector of integers. each integer represents the
// number of union field (0 means the first union field, etc)
// the size of this vector is equal to the number of nested unions in the selection.
typedef std::map<ea_t, intvec_t> user_unions_t;

//--------------------------------------------------------------------------
/// Basic ctree element. This is an abstract class (but we don't use virtual
/// functions in ctree, so the compiler will not disallow you to create citem_t
/// instances). However, elements of pure citem_t type must never be created.
/// Two classes, cexpr_t and cinsn_t are derived from it.
struct citem_t
{
  ea_t ea;              ///< address that corresponds to the item
  ctype_t op;           ///< element type
  int label_num;        ///< label number. -1 means no label. items of expression
                        ///< types (cot_...) should not have labels at the final maturity
                        ///< level, but at the intermediate levels any ctree element
                        ///< may have a label. Labels must be unique. Usually
                        ///< they correspond to the basic block numbers.
  mutable int index;    ///< item index. meaningful only after print_func()
  citem_t(void) : ea(BADADDR), op(cot_empty), label_num(-1), index(-1) {}
  citem_t(ctype_t o) : ea(BADADDR), op(o), label_num(-1), index(-1) {}
  /// Swap two citem_t
  void swap(citem_t &r)
  {
    std::swap(ea, r.ea);
    std::swap(op, r.op);
    std::swap(label_num, r.label_num);
  }
  /// Is an expression?
  bool is_expr(void) const { return op <= cot_last; }
  /// Does the item contain a label?
  bool hexapi contains_label(void) const;
  /// Find parent of the specified item.
  /// \param sitem Item to find the parent of. The search will be performed
  ///            among the children of the item pointed by \c this.
  /// \return NULL if not found
  const citem_t *hexapi find_parent_of(const citem_t *sitem) const;
  citem_t *find_parent_of(const citem_t *item)
  { return CONST_CAST(citem_t*)((CONST_CAST(const citem_t*)(this))->find_parent_of(item)); }
  size_t print1(char *buf, size_t bufsize, const cfunc_t *func) const;
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

/// Ctree element: expression.
/// Depending on the exact expression item type, various fields of this structure are used.
struct cexpr_t : public citem_t
{
  union
  {
    cnumber_t *n;     ///< used for \ref cot_num
    fnumber_t *fpc;   ///< used for \ref cot_fnum
    struct
    {
      union
      {
        var_ref_t v;  ///< used for \ref cot_var
        ea_t obj_ea;  ///< used for \ref cot_obj
      };
      int refwidth;   ///< how many bytes are accessed? (-1: none)
    };
    struct
    {
      cexpr_t *x;     ///< the first operand of the expression
      union
      {
        cexpr_t *y;   ///< the second operand of the expression
        carglist_t *a;///< argument list (used for \ref cot_call)
        uint32 m;     ///< member offset (used for \ref cot_memptr, \ref cot_memref)
                      ///< for unions, the member number
      };
      union
      {
        cexpr_t *z;   ///< the third operand of the expression
        int ptrsize;  ///< memory access size (used for \ref cot_ptr, \ref cot_memptr)
      };
    };
    cinsn_t *insn;    ///< an embedded statement, they are prohibited
                      ///< at the final maturity stage (\ref CMAT_FINAL)
    char *helper;     ///< helper name (used for \ref cot_helper)
    char *string;     ///< string constant (used for \ref cot_str)
  };
  tinfo_t type;       ///< expression type. must be carefully maintained
  int exflags;        ///< \ref EXFL_
/// \defgroup EXFL_ Expression attributes
/// Used in cexpr_t::exflags
//@{
#define EXFL_CPADONE 0x0001 ///< pointer arithmetic correction done
#define EXFL_LVALUE  0x0002 ///< expression is lvalue even if it doesn't look like it
#define EXFL_FPOP    0x0004 ///< floating point operation
#define EXFL_ALONE   0x0008 ///< standalone helper
#define EXFL_CSTR    0x0010 ///< string literal
#define EXFL_PARTIAL 0x0020 ///< type of the expression is considered partial
#define EXFL_ALL     0x003F ///< all currently defined bits
//@}
  /// Pointer arithmetic correction done for this expression?
  bool cpadone(void) const         { return (exflags & EXFL_CPADONE) != 0; }
  bool is_odd_lvalue(void) const   { return (exflags & EXFL_LVALUE) != 0; }
  bool is_fpop(void) const         { return (exflags & EXFL_FPOP) != 0; }
  bool is_cstr(void) const         { return (exflags & EXFL_CSTR) != 0; }
  bool is_type_partial(void) const { return (exflags & EXFL_PARTIAL) != 0; }


  void set_cpadone(void)      { exflags |= EXFL_CPADONE; }
  void set_type_partial(void) { exflags |= EXFL_PARTIAL; }

  cexpr_t(void) : x(NULL), y(NULL), z(NULL), exflags(0) {}
  cexpr_t(ctype_t cop, cexpr_t *_x) : citem_t(cop), x(_x), y(NULL), z(NULL), exflags(0) {}
  cexpr_t(ctype_t cop, cexpr_t *_x, cexpr_t *_y) : citem_t(cop), x(_x), y(_y), z(NULL), exflags(0) {}
  cexpr_t(ctype_t cop, cexpr_t *_x, cexpr_t *_y, cexpr_t *_z) : citem_t(cop), x(_x), y(_y), z(_z), exflags(0) {}
  cexpr_t(mbl_array_t *mba, const lvar_t &v);
  cexpr_t(const cexpr_t &r) : citem_t() { *this = r; }
  void swap(cexpr_t &r) { qswap(*this, r); }
  cexpr_t &operator=(const cexpr_t &r) { return assign(r); }
  cexpr_t &hexapi assign(const cexpr_t &r);
  DECLARE_COMPARISONS(cexpr_t);
  ~cexpr_t(void) { cleanup(); }

  /// Replace the expression.
  /// The children of the expression are abandoned (not freed).
  /// The expression pointed by 'r' is moved to 'this' expression
  /// \param r the source expression. It is deleted after being copied
  void hexapi replace_by(cexpr_t *r);

  /// Cleanup the expression.
  /// This function properly deletes all children and sets the item type to cot_empty.
  void hexapi cleanup(void);

  /// Assign a number to the expression.
  /// \param value number value
  /// \param nbytes size of the number in bytes
  /// \param sign number sign
  void hexapi put_number(cfunc_t *func, uint64 value, int nbytes, type_sign_t sign=no_sign);

  /// Print expression into one line.
  /// \param buf output buffer
  /// \param bufsize size of the output buffer
  /// \param func parent function. This argument is used to find out the referenced variable names.
  /// \return length of the generated text.
  size_t hexapi print1(char *buf, size_t bufsize, const cfunc_t *func) const;

  /// Calculate the type of the expression.
  /// Use this function to calculate the expression type when a new expression is built
  /// \param recursive if true, types of all children expression will be calculated
  ///                  before calculating our type
  void hexapi calc_type(bool recursive);

  /// Compare two expressions.
  /// This function tries to compare two expressions in an 'intelligent' manner.
  /// For example, it knows about commutitive operators and can ignore useless casts.
  /// \param r the expression to compare against the current expression
  /// \return true expressions can be considered equal
  bool hexapi equal_effect(const cexpr_t &r) const;

  /// Verify if the specified item is our parent.
  /// \param parent possible parent item
  /// \return true if the specified item is our parent
  bool hexapi is_child_of(const citem_t *parent) const;

  /// Check if the expression contains the specified operator.
  /// \param needed_op operator code to search for
  /// \param times how many times the operator code should be present
  /// \return true if the expression has at least TIMES children with NEEDED_OP
  bool hexapi contains_operator(ctype_t needed_op, int times=1) const;

  /// Does the expression contain another expression?
  bool contains_expr(const cexpr_t *e) const;
  /// Does the expression contain a comma operator?
  bool contains_comma(int times=1) const { return contains_operator(cot_comma, times); }
  /// Does the expression contain an embedded statement operator?
  bool contains_insn(int times=1) const { return contains_operator(cot_insn, times); }
  /// Does the expression contain an embedded statement operator or a label?
  bool contains_insn_or_label(void) const { return contains_insn() || contains_label(); }
  /// Does the expression contain a comma operator or an embedded statement operator or a label?
  bool contains_comma_or_insn_or_label(int maxcommas=1) const { return contains_comma(maxcommas) || contains_insn_or_label(); }
  /// Is nice expression?
  /// Nice expressions do not contain comma operators, embedded statements, or labels.
  bool is_nice_expr(void) const { return !contains_comma_or_insn_or_label(); }
  /// Is nice condition?.
  /// Nice condition is a nice expression of the boolean type.
  bool is_nice_cond(void) const { return is_nice_expr() && type.is_bool(); }
  /// Is call object?
  /// \return true if our expression is the call object of the specified parent expression.
  bool is_call_object_of(const citem_t *parent) const { return parent != NULL && parent->op == cot_call && ((cexpr_t*)parent)->x == this; }
  /// Is call argument?
  /// \return true if our expression is a call argument of the specified parent expression.
  bool is_call_arg_of(const citem_t *parent) const { return parent != NULL && parent->op == cot_call && ((cexpr_t*)parent)->x != this; }
  /// Get expression sign
  type_sign_t get_type_sign(void) const { return type.get_sign(); }
  /// Is expression unsigned?
  bool is_type_unsigned(void) const { return type.is_unsigned(); }
  /// Is expression signed?
  bool is_type_signed(void) const { return type.is_signed(); }
  /// Get max number of bits that can really be used by the expression.
  /// For example, x % 16 can yield only 4 non-zero bits
  int hexapi get_high_nbit_bound(int pbits, type_sign_t psign, bool *p_maybe_negative=NULL) const;
  /// Get min number of bits that are always present in the expression.
  /// For example, 16 always uses 5 bits.
  int hexapi get_low_nbit_bound(type_sign_t psign, bool *p_maybe_negative=NULL) const;
  /// Check if the expression requires an lvalue.
  /// \param child The function will check if this child of our expression must be an lvalue.
  /// \return true if child must be an lvalue.
  bool hexapi requires_lvalue(const cexpr_t *child) const;
  /// Check if the expression has side effects.
  /// Calls, pre/post inc/dec, and assignments have side effects.
  bool hexapi has_side_effects(void) const;
  /// Check if the expression if aliasable.
  /// Simple registers and non-aliasble stack slots return false.
  bool is_aliasable(void) const;
  /// Get numeric value of the expression.
  /// This function can be called only on cot_num expressions!
  uint64 numval(void) const
  {
    QASSERT(50071, op == cot_num);
    return n->value(type);
  }
  /// Check if the expression is a number with the specified value.
  bool is_const_value(uint64 _v) const
  {
    return op == cot_num && numval() == _v;
  }
  /// Check if the expression is a negative number.
  bool is_negative_const(void) const
  {
    return op == cot_num && int64(numval()) < 0;
  }
  /// Check if the expression is a non-zero number.
  bool is_non_zero_const(void) const
  {
    return op == cot_num && numval() != 0;
  }
  /// Check if the expression is a zero.
  bool is_zero_const(void) const { return is_const_value(0); }
  /// Get expression value.
  /// \param out Pointer to the variable where the expression value is returned.
  /// \return true if the expression is a number.
  bool get_const_value(uint64 *out) const
  {
    if ( op == cot_num )
    {
      if ( out != NULL )
        *out = numval();
      return true;
    }
    return false;
  }
  /// May the expression be a pointer?
  bool maybe_ptr(void) const
  {
    uint64 val;
    if ( get_const_value(&val)
      && (ea_t(val) != val || !is_mapped((ea_t)val)) )
    {
      return false;
    }
    return true;
  }
  /// Find pointer or array child.
  cexpr_t *get_ptr_or_array(void)
  {
    if ( x->type.is_ptr_or_array() )
      return x;
    if ( y->type.is_ptr_or_array() )
      return y;
    return NULL;
  }
  /// Find the child with the specified operator.
  const cexpr_t *find_op(ctype_t _op) const
  {
    if ( x->op == _op )
      return x;
    if ( y->op == _op )
      return y;
    return NULL;
  }
  cexpr_t *find_op(ctype_t _op)
  {
    return (cexpr_t *)((const cexpr_t *)this)->find_op(_op);
  }

  /// Find the operand with a numeric value
  const cexpr_t *find_num_op(void) const { return find_op(cot_num); }
        cexpr_t *find_num_op(void)       { return find_op(cot_num); }
  /// Find the pointer operand.
  /// This function returns the pointer operand for binary expressions.
  const cexpr_t *find_ptr_or_array(bool remove_eqsize_casts) const;
  /// Get the other operand.
  /// This function returns the other operand (not the specified one)
  /// for binary expressions.
  const cexpr_t *theother(const cexpr_t *what) const { return what == x ? y : x; }
        cexpr_t *theother(const cexpr_t *what)       { return what == x ? y : x; }

  // these are inline functions, see below
  bool get_1num_op(cexpr_t **o1, cexpr_t **o2);
  bool get_1num_op(const cexpr_t **o1, const cexpr_t **o2) const;

};//-

/// Statement with an expression.
/// This is a base class for various statements with expressions.
struct ceinsn_t
{
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  cexpr_t expr;         ///< Expression of the statement
};

/// Should curly braces be printed?
enum use_curly_t
{
  CALC_CURLY_BRACES,    ///< print curly braces if necessary
  NO_CURLY_BRACES,      ///< don't print curly braces
  USE_CURLY_BRACES,     ///< print curly braces without any checks
};

/// If statement
struct cif_t : public ceinsn_t
{
  cinsn_t *ithen;       ///< Then-branch of the if-statement
  cinsn_t *ielse;       ///< Else-branch of the if-statement. May be NULL.
  cif_t(void) : ithen(NULL), ielse(NULL) {}
  cif_t(const cif_t &r) : ceinsn_t(), ithen(NULL), ielse(NULL) { *this = r; }
  cif_t &operator=(const cif_t &r) { return assign(r); }
  cif_t &hexapi assign(const cif_t &r);
  DECLARE_COMPARISONS(cif_t);
  ~cif_t(void) { cleanup(); }
  void cleanup(void);
};

/// Base class for loop statements
struct cloop_t : public ceinsn_t
{
  cinsn_t *body;
  cloop_t(void) : body(NULL) {}
  cloop_t(cinsn_t *b) : body(b) {}
  cloop_t(const cloop_t &r) : ceinsn_t(), body(NULL) { *this = r; }
  cloop_t &operator=(const cloop_t &r) { return assign(r); }
  cloop_t &hexapi assign(const cloop_t &r);
  ~cloop_t(void) { cleanup(); }
  void cleanup(void);
};

/// For-loop
struct cfor_t : public cloop_t
{
  cexpr_t init;                 ///< Initialization expression
  cexpr_t step;                 ///< Step expression
  DECLARE_COMPARISONS(cfor_t);
};

/// While-loop
struct cwhile_t : public cloop_t
{
  DECLARE_COMPARISONS(cwhile_t);
};

/// Do-loop
struct cdo_t : public cloop_t
{
  DECLARE_COMPARISONS(cdo_t);
};

/// Return statement
struct creturn_t : public ceinsn_t
{
  DECLARE_COMPARISONS(creturn_t);
};

/// Goto statement
struct cgoto_t
{
  int label_num;        ///< Target label number
  DECLARE_COMPARISONS(cgoto_t);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void print(const citem_t *parent, int indent, vc_printer_t &vp) const;
};

/// asm statement
struct casm_t : public eavec_t
{
  casm_t(ea_t ea) { push_back(ea); }
  casm_t(const casm_t &r) : eavec_t(eavec_t(r)) {}
  DECLARE_COMPARISONS(casm_t);
  void print(const citem_t *parent, int indent, vc_printer_t &vp) const;
  bool one_insn(void) const { return size() == 1; }
  void genasm(qstring *buf, ea_t ea) const;
};

/// Vector of pointers to statements.
typedef qvector<cinsn_t *> cinsnptrvec_t;

/// Ctree element: statement.
/// Depending on the exact statement type, various fields of the union are used.
struct cinsn_t : public citem_t
{
  union
  {
    cblock_t *cblock;   ///< details of block-statement
    cexpr_t *cexpr;     ///< details of expression-statement
    cif_t *cif;         ///< details of if-statement
    cfor_t *cfor;       ///< details of for-statement
    cwhile_t *cwhile;   ///< details of while-statement
    cdo_t *cdo;         ///< details of do-statement
    cswitch_t *cswitch; ///< details of switch-statement
    creturn_t *creturn; ///< details of return-statement
    cgoto_t *cgoto;     ///< details of goto-statement
    casm_t *casm;       ///< details of asm-statement
  };

  cinsn_t(void) : citem_t(cit_empty) {}
  cinsn_t(const cinsn_t &r) : citem_t(cit_empty) { *this = r; }
  void swap(cinsn_t &r) { citem_t::swap(r); std::swap(cblock, r.cblock); }
  cinsn_t &operator=(const cinsn_t &r) { return assign(r); }
  cinsn_t &hexapi assign(const cinsn_t &r);
  DECLARE_COMPARISONS(cinsn_t);
  ~cinsn_t(void) { cleanup(); }

  /// Replace the statement.
  /// The children of the statement are abandoned (not freed).
  /// The statement pointed by 'r' is moved to 'this' statement
  /// \param r the source statement. It is deleted after being copied
  void hexapi replace_by(cinsn_t *r);

  /// Cleanup the statement.
  /// This function properly deletes all children and sets the item type to cit_empty.
  void hexapi cleanup(void);

  /// Overwrite with zeroes without cleaning memory or deleting children
  void zero(void) { op = cit_empty; cblock = NULL; }

  /// Create a new statement.
  /// The current statement must be a block. The new statement will be appended to it.
  /// \param insn_ea statement address
  cinsn_t &hexapi new_insn(ea_t insn_ea);

  /// Create a new if-statement.
  /// The current statement must be a block. The new statement will be appended to it.
  /// \param cnd if condition. It will be deleted after being copied.
  cif_t &hexapi create_if(cexpr_t *cnd);

  /// Print the statement into many lines.
  /// \param indent indention (number of spaces) for the statement
  /// \param vp printer helper class which will receive the generated text.
  /// \param use_curly if the statement is a block, how should curly braces be printed.
  void hexapi print(int indent, vc_printer_t &vp, use_curly_t use_curly=CALC_CURLY_BRACES) const;

  /// Print the statement into one line.
  /// Currently this function is not available.
  /// \param buf output buffer
  /// \param bufsize size of output buffer
  /// \param func parent function. This argument is used to find out the referenced variable names.
  /// \return length of the generated text.
  size_t hexapi print1(char *buf, size_t bufsize, const cfunc_t *func) const;

  /// Check if the statement passes execution to the next statement.
  /// \return false if the statement breaks the control flow (like goto, return, etc)
  bool hexapi is_ordinary_flow(void) const;

  /// Check if the statement contains a statement of the specified type.
  /// \param type statement opcode to look for
  /// \param times how many times TYPE should be present
  /// \return true if the statement has at least TIMES children with opcode == TYPE
  bool hexapi contains_insn(ctype_t type, int times=1) const;

  /// Collect free \c break statements.
  /// This function finds all free \c break statements within the current statement.
  /// A \c break statement is free if it does not have a loop or switch parent that
  /// that is also within the current statement.
  /// \param breaks pointer to the variable where the vector of all found free
  ///               \c break statements is returned. This argument can be NULL.
  /// \return true if some free \c break statements have been found
  bool hexapi collect_free_breaks(cinsnptrvec_t *breaks);

  /// Collect free \c continue statements.
  /// This function finds all free \c continue statements within the current statement.
  /// A \c continue statement is free if it does not have a loop parent that
  /// that is also within the current statement.
  /// \param continues pointer to the variable where the vector of all found free
  ///               \c continue statements is returned. This argument can be NULL.
  /// \return true if some free \c continue statements have been found
  bool hexapi collect_free_continues(cinsnptrvec_t *continues);

  /// Check if the statement has free \c break statements.
  bool contains_free_break(void) const { return CONST_CAST(cinsn_t*)(this)->collect_free_breaks(NULL); }
  /// Check if the statement has free \c continue statements.
  bool contains_free_continue(void) const { return CONST_CAST(cinsn_t*)(this)->collect_free_continues(NULL); }

};//-

/// Compound statement (curly braces)
struct cblock_t : public qlist<cinsn_t> // we need list to be able to manipulate
{                                       // its elements freely
  DECLARE_COMPARISONS(cblock_t);
};

/// Function argument
struct carg_t : public cexpr_t
{
  bool is_vararg;             ///< is a vararg (matches ...)
  tinfo_t formal_type;        ///< formal parameter type (if known)
  void consume_cexpr(cexpr_t *e)
  {
    qswap(*(cexpr_t*)this, *e);
    delete e;
  }
  carg_t(void) : is_vararg(false) {}
  DECLARE_COMPARISONS(carg_t)
  {
    return cexpr_t::compare(r);
  }
};
DECLARE_TYPE_AS_MOVABLE(carg_t);

/// Function argument list
struct carglist_t : public qvector<carg_t>
{
  tinfo_t functype;   ///< function object type
  carglist_t(void) {}
  carglist_t(const tinfo_t &ftype) : functype(ftype) {}
  DECLARE_COMPARISONS(carglist_t);
  size_t print(char *buf, size_t bufsize, const cfunc_t *func) const;
  int print(int curpos, vc_printer_t &vp) const;
};

/// Switch case. Usually cinsn_t is a block
struct ccase_t : public cinsn_t
{
  qvector<uint64> values;    ///< List of case values.
                             ///< if empty, then 'default' case
  DECLARE_COMPARISONS(ccase_t);
  void print(const cinsn_t *parent, int indent, vc_printer_t &vp) const;
  void set_insn(cinsn_t *i); // deletes 'i'
  size_t size(void) const { return values.size(); }
  const uint64 &value(int i) const { return values[i]; }
};
DECLARE_TYPE_AS_MOVABLE(ccase_t);

/// Vector of switch cases
struct ccases_t : public qvector<ccase_t>
{
  DECLARE_COMPARISONS(ccases_t);
  void print(const cinsn_t *parent, int indent, vc_printer_t &vp) const;
  int find_value(uint64 v) const;
};

/// Switch statement
struct cswitch_t : public ceinsn_t
{
  cnumber_t mvnf;       ///< Maximal switch value and number format
  ccases_t cases;       ///< Switch cases: values and instructions
  DECLARE_COMPARISONS(cswitch_t);
};

//---------------------------------------------------------------------------
/// Invisible COLOR_ADDR tags in the output text are used to refer to ctree items and variables
struct ctree_anchor_t
{
  uval_t value;
#define ANCHOR_INDEX  0x1FFFFFFF
#define ANCHOR_MASK   0xC0000000
#define   ANCHOR_CITEM 0x00000000 ///< c-tree item
#define   ANCHOR_LVAR  0x40000000 ///< declaration of local variable
#define   ANCHOR_ITP   0x80000000 ///< item type preciser
#define ANCHOR_BLKCMT 0x20000000  ///< block comment (for ctree items)
  ctree_anchor_t(void) : value(BADADDR) {}
  int get_index(void) const { return value & ANCHOR_INDEX; }
  item_preciser_t get_itp(void) const { return item_preciser_t(value & ~ANCHOR_ITP); }
  bool is_valid_anchor(void) const { return value != BADADDR; }
  bool is_citem_anchor(void) const { return (value & ANCHOR_MASK) == ANCHOR_CITEM; }
  bool is_lvar_anchor(void) const { return (value & ANCHOR_MASK) == ANCHOR_LVAR; }
  bool is_itp_anchor(void) const { return (value & ANCHOR_ITP) != 0; }
  bool is_blkcmt_anchor(void) const { return (value & ANCHOR_BLKCMT) != 0; }
};

/// Type of the cursor item.
enum cursor_item_type_t
{
  VDI_NONE, ///< undefined
  VDI_EXPR, ///< c-tree item
  VDI_LVAR, ///< declaration of local variable
  VDI_FUNC, ///< the function itself (the very first line with the function prototype)
  VDI_TAIL, ///< cursor is at (beyond) the line end (commentable line)
};

/// Cursor item.
/// Information about the item under the cursor
struct ctree_item_t
{
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  cursor_item_type_t citype; ///< Item type
  union
  {
    citem_t *it;
    cexpr_t *e;         ///< VDI_EXPR: Expression
    cinsn_t *i;         ///< VDI_EXPR: Statement
    lvar_t *l;          ///< VDI_LVAR: Local variable
    cfunc_t *f;         ///< VDI_FUNC: Function
    treeloc_t loc;      ///< VDI_TAIL: Line tail
  };
  void verify(const mbl_array_t *mba) const;

  /// Get pointer to structure member.
  /// If the current item is a structure field,
  /// this function will return pointer to its definition.
  /// \return NULL if failed
  /// \param[out] p_sptr pointer to the variable where the pointer to the
  ///               parent structure is returned. This parameter can be NULL.

  member_t *hexapi get_memptr(struc_t **p_sptr=NULL) const;

  /// Get pointer to local variable.
  /// If the current item is a local variable,
  /// this function will return pointer to its definition.
  /// \return NULL if failed

  lvar_t *hexapi get_lvar(void) const;


  /// Get address of the current item.
  /// Each ctree item has an address.
  /// \return BADADDR if failed

  ea_t hexapi get_ea(void) const;


  /// Get label number of the current item.
  /// \param[in] gln_flags Combination of \ref GLN_ bits
  /// \return -1 if failed or no label

  int hexapi get_label_num(int gln_flags) const;
/// \defgroup GLN_ get_label_num control
//@{
#define GLN_CURRENT     0x01 ///< get label of the current item
#define GLN_GOTO_TARGET 0x02 ///< get goto target
#define GLN_ALL         0x03 ///< get both
//@}

  /// Is the current item is a ctree item?
  bool is_citem(void) const { return citype == VDI_EXPR; }

};

/// Unused label disposition.
enum allow_unused_labels_t
{
  FORBID_UNUSED_LABELS = 0,     ///< Unused labels cause interr
  ALLOW_UNUSED_LABELS = 1,      ///< Unused labels are permitted
};

typedef std::map<int, qstring> user_labels_t;

/// Logically negate the specified expression.
/// The specified expression will be logically negated.
/// For example, "x == y" is converted into "x != y" by this function.
/// \param e expression to negate. After the call, e must not be used anymore
///          because it can be changed by the function. The function return value
///          must be used to refer to the expression.
/// \return logically negated expression.

cexpr_t *hexapi lnot(cexpr_t *e);


/// Create a new block-statement.

cinsn_t *hexapi new_block(void);


/// Create a helper object.
/// This function creates a helper object.
/// The named function is not required to exist, the decompiler will only print
/// its name in the output. Helper functions are usually used to represent arbitrary
/// function or macro calls in the output.
/// \param standalone false:helper must be called; true:helper can be used in any expression
/// \param type type of the create function object
/// \param format printf-style format string that will be used to create the function name.
/// \param va additional arguments for printf
/// \return the created expression.

AS_PRINTF(3, 0) cexpr_t *hexapi vcreate_helper(bool standalone, const tinfo_t &type, const char *format, va_list va);

/// Create a helper object..
AS_PRINTF(3, 4) inline cexpr_t *create_helper(bool standalone, const tinfo_t &type, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  cexpr_t *e = vcreate_helper(standalone, type, format, va);
  va_end(va);
  return e;
}


/// Create a helper call expression.
/// This function creates a new expression: a call of a helper function.
/// \param rettype type of the whole expression.
/// \param args helper arguments. this object will be consumed by the function.
///             if there are no args, this parameter may be specified as NULL.
/// \param format printf-style format string that will be used to create the function name.
/// \param va additional arguments for printf
/// \return the created expression.

AS_PRINTF(3, 0) cexpr_t *hexapi vcall_helper(const tinfo_t &rettype, carglist_t *args, const char *format, va_list va);

/// Create a helper call.
AS_PRINTF(3, 4) inline cexpr_t *call_helper(
        const tinfo_t &rettype,
        carglist_t *args,
        const char *format, ...)
{
  va_list va;
  va_start(va, format);
  cexpr_t *e = vcall_helper(rettype, args, format, va);
  va_end(va);
  return e;
}


/// Create a number expression
/// \param n value
/// \param sign number sign

cexpr_t *hexapi make_num(uint64 n, cfunc_t *func=NULL, ea_t ea=BADADDR, int opnum=0, type_sign_t sign=no_sign, int size=0);


/// Create a reference.
/// This function performs the following conversion: "obj" => "&obj".
/// It can handle casts, annihilate "&*", and process other special cases.

cexpr_t *hexapi make_ref(cexpr_t *e);


/// Dereference a pointer.
/// This function dereferences a pointer expression.
/// It performs the following conversion: "ptr" => "*ptr"
/// It can handle discrepancies in the pointer type and the access size.
/// \param e expression to deference
/// \param ptrsize access size
/// \return dereferenced expression

cexpr_t *hexapi dereference(cexpr_t *e, int ptrsize, bool is_flt=false);


/// Save user defined labels into the database.
/// \param func_ea the entry address of the function
/// \param user_labels collection of user defined labels

void hexapi save_user_labels(ea_t func_ea, const user_labels_t *user_labels);


/// Save user defined comments into the database.
/// \param func_ea the entry address of the function
/// \param user_cmts collection of user defined comments

void hexapi save_user_cmts(ea_t func_ea, const user_cmts_t *user_cmts);

/// Save user defined number formats into the database.
/// \param func_ea the entry address of the function
/// \param numforms collection of user defined comments

void hexapi save_user_numforms(ea_t func_ea, const user_numforms_t *numforms);


/// Save user defined citem iflags into the database.
/// \param func_ea the entry address of the function
/// \param iflags collection of user defined citem iflags

void hexapi save_user_iflags(ea_t func_ea, const user_iflags_t *iflags);


/// Save user defined union field selections into the database.
/// \param func_ea the entry address of the function
/// \param unions collection of union field selections

void hexapi save_user_unions(ea_t func_ea, const user_unions_t *unions);


/// Restore user defined labels from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined labels.
///         The returned object must be deleted by the caller using delete_user_labels()

user_labels_t *hexapi restore_user_labels(ea_t func_ea);


/// Restore user defined comments from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined comments.
///         The returned object must be deleted by the caller using delete_user_cmts()

user_cmts_t *hexapi restore_user_cmts(ea_t func_ea);


/// Restore user defined number formats from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined number formats.
///         The returned object must be deleted by the caller using delete_user_numforms()

user_numforms_t *hexapi restore_user_numforms(ea_t func_ea);


/// Restore user defined citem iflags from the database.
/// \param func_ea the entry address of the function
/// \return collection of user defined iflags.
///         The returned object must be deleted by the caller using delete_user_iflags()

user_iflags_t *hexapi restore_user_iflags(ea_t func_ea);


/// Restore user defined union field selections from the database.
/// \param func_ea the entry address of the function
/// \return collection of union field selections
///         The returned object must be deleted by the caller using delete_user_unions()

user_unions_t *hexapi restore_user_unions(ea_t func_ea);


typedef std::map<ea_t, cinsnptrvec_t> eamap_t;
// map of instruction boundaries. may contain INS_EPILOG for the epilog instructions
typedef std::map<cinsn_t *, rangeset_t> boundaries_t;
#define INS_EPILOG ((cinsn_t *)1)
// Tags to find this location quickly: #cfunc_t #func_t
//-------------------------------------------------------------------------
/// Decompiled function. Decompilation result is kept here.
struct cfunc_t
{
  ea_t entry_ea;             ///< function entry address
  mbl_array_t *mba;          ///< underlying microcode
  cinsn_t body;              ///< function body, must be a block
  intseq_t &argidx;          ///< list of arguments (indexes into vars)
  ctree_maturity_t maturity; ///< maturity level
  // The following maps must be accessed using helper functions.
  // Example: for user_labels_t, see functions starting with "user_labels_".
  user_labels_t *user_labels;///< user-defined labels.
  user_cmts_t *user_cmts;    ///< user-defined comments.
  user_numforms_t *numforms; ///< user-defined number formats.
  user_iflags_t *user_iflags;///< user-defined item flags \ref CIT_
  user_unions_t *user_unions;///< user-defined union field selections.
/// \defgroup CIT_ ctree item iflags bits
//@{
#define CIT_COLLAPSED 0x0001 ///< display element in collapsed form
//@}
  int refcnt;                ///< reference count to this object. use cfuncptr_t
  int statebits;             ///< current cfunc_t state. see \ref CFS_
/// \defgroup CFS_ cfunc state bits
#define CFS_BOUNDS       0x0001 ///< 'eamap' and 'boundaries' are ready
#define CFS_TEXT         0x0002 ///< 'sv' is ready (and hdrlines)
#define CFS_LVARS_HIDDEN 0x0004 ///< local variable definitions are collapsed
  eamap_t *eamap;            ///< ea->insn map. use \ref get_eamap
  boundaries_t *boundaries;  ///< map of instruction boundaries. use \ref get_boundaries
  strvec_t sv;               ///< decompilation output: function text. use \ref get_pseudocode
  int hdrlines;              ///< number of lines in the declaration area
  mutable ctree_items_t treeitems; ///< vector of ctree items

public:
  cfunc_t(mbl_array_t *mba);
  ~cfunc_t(void) { cleanup(); }
  void release(void) { delete this; }
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  /// Generate the function body.
  /// This function (re)generates the function body from the underlying microcode.
  void hexapi build_c_tree(void);

  /// Verify the ctree.
  /// This function verifies the ctree. If the ctree is malformed, an internal error
  /// is generated. Use it to verify the ctree after your modifications.
  /// \param aul Are unused labels acceptable?
  /// \param even_without_debugger if false and there is no debugger, the verification will be skipped
  void hexapi verify(allow_unused_labels_t aul, bool even_without_debugger) const;

  /// Print function prototype.
  /// \param buf output buffer
  /// \param bufsize size of the output buffer
  /// \return length of the generated text
  size_t hexapi print_dcl(char *buf, int bufsize) const;
  size_t hexapi print_dcl2(qstring *out) const;

  /// Print function text.
  /// \param vp printer helper class to receive the generated text.
  void hexapi print_func(vc_printer_t &vp) const;

  /// Get the function type.
  /// \param type variable where the function type is returned
  /// \param fields variable where the argument names are returned
  /// \return false if failure
  bool hexapi get_func_type(tinfo_t *type) const;

  /// Get vector of local variables.
  /// \return pointer to the vector of local variables. If you modify this vector,
  ///         the ctree must be regenerated in order to have correct cast operators.
  ///         Use build_c_tree() for that.
  ///         Removing lvars should be done carefully: all references in ctree
  ///         and microcode must be corrected after that.
  lvars_t *hexapi get_lvars(void);

  /// Get stack offset delta.
  /// The local variable stack offsets retreived by v.location.stkoff()
  /// should be adjusted before being used as stack frame offsets in IDA.
  /// \return the delta to apply.
  ///         example: ida_stkoff = v.location.stkoff() - f->get_stkoff_delta()
  sval_t hexapi get_stkoff_delta(void);

  /// Find the label.
  /// \return pointer to the ctree item with the specified label number.
  citem_t *hexapi find_label(int label);

  /// Remove unused labels.
  /// This function check what labels are really used by the function and
  /// removes the unused ones.
  void hexapi remove_unused_labels(void);

  /// Retrieve a user defined comment.
  /// \param loc ctree location
  /// \param rt should already retrieved comments retrieved again?
  /// \return pointer to the comment string or NULL
  const char *hexapi get_user_cmt(const treeloc_t &loc, cmt_retrieval_type_t rt) const;

  /// Set a user defined comment.
  /// This function stores the specified comment in the cfunc_t structure.
  /// The save_user_cmts() function must be called after it.
  /// \param loc ctree location
  /// \param cmt new comment. if empty or NULL, then an existing comment is deleted.
  void hexapi set_user_cmt(const treeloc_t &loc, const char *cmt);

  /// Retrieve citem iflags.
  /// \param loc citem locator
  /// \return \ref CIT_ or 0
  int32 hexapi get_user_iflags(const citem_locator_t &loc) const;

  /// Set citem iflags.
  /// \param loc citem locator
  /// \param iflags new iflags
  void hexapi set_user_iflags(const citem_locator_t &loc, int32 iflags);

  /// Check if there are orphan comments.
  bool hexapi has_orphan_cmts(void) const;

  /// Delete all orphan comments.
  /// The save_user_cmts() function must be called after this call.
  int hexapi del_orphan_cmts(void);

  /// Retrieve a user defined union field selection.
  /// \param ea address
  /// \param path out: path describing the union selection.
  /// \return pointer to the path or NULL
  bool hexapi get_user_union_selection(ea_t ea, intvec_t *path);

  /// Set a union field selection.
  /// The save_user_unions() function must be called after calling this function.
  /// \param ea address
  /// \param path in: path describing the union selection.
  void hexapi set_user_union_selection(ea_t ea, const intvec_t &path);

  /// Save user-defined labels into the database
  void save_user_labels(void) const { ::save_user_labels(entry_ea, user_labels); }
  /// Save user-defined comments into the database
  void save_user_cmts(void) const { ::save_user_cmts(entry_ea, user_cmts); }
  /// Save user-defined number formats into the database
  void save_user_numforms(void) const { ::save_user_numforms(entry_ea, numforms); }
  /// Save user-defined iflags into the database
  void save_user_iflags(void) const { ::save_user_iflags(entry_ea, user_iflags); }
  /// Save user-defined union field selections into the database
  void save_user_unions(void) const { ::save_user_unions(entry_ea, user_unions); }

  /// Get ctree item for the specified cursor position.
  /// \return false if failed to get the current item
  /// \param line line of decompilation text (element of \ref sv)
  /// \param x x cursor coordinate in the line
  /// \param is_ctree_line does the line belong to statement area? (if not, it is assumed to belong to the declaration area)
  /// \param phead ptr to the first item on the line (used to attach block comments). May be NULL
  /// \param pitem ptr to the current item. May be NULL
  /// \param ptail ptr to the last item on the line (used to attach indented comments). May be NULL
  /// \sa vdui_t::get_current_item()
  bool hexapi get_line_item(const char *line, int x, bool is_ctree_line, ctree_item_t *phead, ctree_item_t *pitem, ctree_item_t *ptail);

  /// Get information about decompilation warnings.
  /// \return reference to the vector of warnings
  hexwarns_t &hexapi get_warnings(void);

  /// Get pointer to ea->insn map.
  /// This function initializes eamap if not done yet.
  eamap_t &hexapi get_eamap(void);

  /// Get pointer to map of instruction boundaries.
  /// This function initializes the boundary mapp if not done yet.
  boundaries_t &hexapi get_boundaries(void);

  /// Get pointer to decompilation output: the pseudocode.
  /// This function generates pseudocode if not done yet.
  strvec_t &hexapi get_pseudocode(void);

  bool hexapi gather_derefs(const ctree_item_t &ci, udt_type_data_t *udm=NULL) const;
private:
  /// Cleanup.
  /// Properly delete all children and free memory.
  void hexapi cleanup(void);
  DECLARE_UNCOPYABLE(cfunc_t)
};
typedef qrefcnt_t<cfunc_t> cfuncptr_t;


/// Decompile a function.
/// Multiple decompilations of the same function return the same object.
/// \param pfn pointer to function to decompile
/// \param hf extended error information (if failed)
/// \return pointer to the decompilation result (a reference counted pointer).
///         NULL if failed.

cfuncptr_t hexapi decompile(func_t *pfn, hexrays_failure_t *hf);


/// Flush the cached decompilation results.
/// Erases a cache entry for the specified function.
/// \param ea function to erase from the cache
/// \return if a cache entry existed.

bool hexapi mark_cfunc_dirty(ea_t ea);


/// Flush all cached decompilation results.

void hexapi clear_cached_cfuncs(void);


/// Do we have a cached decompilation result for 'ea'?

bool hexapi has_cached_cfunc(ea_t ea);

//--------------------------------------------------------------------------
// Now cinsn_t class is defined, define the cleanup functions:
inline void cif_t::cleanup(void)     { delete ithen; delete ielse; }
inline void cloop_t::cleanup(void)   { delete body; }

/// Print item into one line.
/// \param buf output buffer
/// \param bufsize size of the output buffer
/// \param func parent function. This argument is used to find out the referenced variable names.
/// \return length of the generated text.

inline size_t citem_t::print1(char *buf, size_t bufsize, const cfunc_t *func) const
{
  if ( is_expr() )
    return ((cexpr_t*)this)->print1(buf, bufsize, func);
  else
    return ((cinsn_t*)this)->print1(buf, bufsize, func);
}

/// Get pointers to operands. at last one operand should be a number
/// o1 will be pointer to the number

inline bool cexpr_t::get_1num_op(cexpr_t **o1, cexpr_t **o2)
{
  if ( x->op == cot_num )
  {
    *o1 = x;
    *o2 = y;
  }
  else
  {
    if ( y->op != cot_num )
      return false;
    *o1 = y;
    *o2 = x;
  }
  return true;
}

inline bool cexpr_t::get_1num_op(const cexpr_t **o1, const cexpr_t **o2) const
{
  return CONST_CAST(cexpr_t*)(this)->get_1num_op(
         CONST_CAST(cexpr_t**)(o1),
         CONST_CAST(cexpr_t**)(o2));
}

inline citem_locator_t::citem_locator_t(const citem_t *i) : ea(i->ea), op(i->op)
{
}

const char *hexapi get_ctype_name(ctype_t op);
qstring hexapi create_field_name(const tinfo_t &type, uval_t offset=BADADDR);
typedef void *hexdsp_t(int code, ...);
const int64 HEXRAYS_API_MAGIC = 0x00DEC0DE00000001LL;

/// Decompiler events.
/// Use install_hexrays_callback() to install a handler for decompiler events.
/// When the possible return value is not specified, your callback
/// must return zero.
enum hexrays_event_t
{
  // When a function is decompiled, the following events occur:

  hxe_flowchart,        ///< Flowchart has been generated.
                        ///< qflow_chart_t *fc

  hxe_prolog,           ///< Prolog analysis has been finished.
                        ///< mbl_array_t *mba                                 \n
                        ///< qflow_chart_t *fc                                \n
                        ///< bitset_t *reachable_blocks

  hxe_preoptimized,     ///< Microcode has been preoptimized.
                        ///< mbl_array_t *mba

  hxe_locopt,           ///< Basic block level optimization has been finished.
                        ///< mbl_array_t *mba

  hxe_prealloc,         ///< Local variables: preallocation step begins.      \n
                        ///< mbl_array_t *mba                                 \n
                        ///< This event may occur several times               \n
                        ///< Should return: 1 if modified microcode           \n
                        ///< Negative values are \ref MERR_ error codes

  hxe_glbopt,           ///< Global optimization has been finished.
                        ///< mbl_array_t *mba

  hxe_structural,       ///< Structural analysis has been finished.
                        ///< control_graph_t *ct

  hxe_maturity,         ///< Ctree maturity level is being changed.
                        ///< cfunc_t *cfunc                                   \n
                        ///< ctree_maturity_t new_maturity

  hxe_interr,           ///< Internal error has occurred.
                        ///< int errcode

  hxe_combine,          ///< Trying to combine instructions of basic block.
                        ///< mblock_t *blk                                    \n
                        ///< minsn_t *insn                                    \n
                        ///< Should return: 1 if combined the current instruction
                        ///< with a preceding one

  hxe_print_func,       ///< Printing ctree and generating text.
                        ///< cfunc_t *cfunc                                   \n
                        ///< vc_printer_t *vp                                 \n
                        ///< Returns: 1 if text has been generated by the plugin

  hxe_func_printed,     ///< Function text has been generated. Plugins may
                        ///< modify the text in \ref sv.
                        ///< cfunc_t *cfunc

  hxe_resolve_stkaddrs, ///< The optimizer is about to resolve stack addresses.
                        ///< mbl_array_t *mba

  // User interface related events:

  hxe_open_pseudocode=100,
                        ///< New pseudocode view has been opened.
                        ///< vdui_t *vu

  hxe_switch_pseudocode,///< Existing pseudocode view has been reloaded
                        ///< with a new function. Its text has not been
                        ///< refreshed yet, only cfunc and mba pointers are ready.\n
                        ///< vdui_t *vu

  hxe_refresh_pseudocode,///< Existing pseudocode text has been refreshed.
                        ///< Adding/removing pseudocode lines is forbidden in this event.
                        ///< This event is obsolete, please use \ref hxe_func_printed.
                        ///< vdui_t *vu                                       \n
                        ///< See also hxe_text_ready, which happens earlier

  hxe_close_pseudocode, ///< Pseudocode view is being closed.
                        ///< vdui_t *vu

  hxe_keyboard,         ///< Keyboard has been hit.
                        ///< vdui_t *vu                                       \n
                        ///< int key_code (VK_...)                            \n
                        ///< int shift_state                                  \n
                        ///< Should return: 1 if the event has been handled

  hxe_right_click,      ///< Mouse right click.
                        ///< Use hxe_populating_popup instead, in case you
                        ///< want to add items in the popup menu.
                        ///< vdui_t *vu

  hxe_double_click,     ///< Mouse double click.
                        ///< vdui_t *vu                                       \n
                        ///< int shift_state                                  \n
                        ///< Should return: 1 if the event has been handled

  hxe_curpos,           ///< Current cursor position has been changed.
                        ///< (for example, by left-clicking or using keyboard)\n
                        ///< vdui_t *vu

  hxe_create_hint,      ///< Create a hint for the current item.
                        ///< vdui_t *vu                                       \n
                        ///< qstring *result_hint                             \n
                        ///< int *implines                                    \n
                        ///< Possible return values:                          \n
                        ///<  0: the event has not been handled               \n
                        ///<  1: hint has been created (should set *implines to nonzero as well)\n
                        ///<  2: hint has been created but the standard hints must be
                        ///<     appended by the decompiler

  hxe_text_ready,       ///< Decompiled text is ready.
                        ///< vdui_t *vu                                       \n
                        ///< This event can be used to modify the output text (sv).
                        ///< The text uses regular color codes (see lines.hpp)
                        ///< COLOR_ADDR is used to store pointers to ctree elements

  hxe_populating_popup, ///< Populating popup menu. We can add menu items now.
                        ///< TWidget *widget
                        ///< TPopupMenu *popup_handle
                        ///< vdui_t *vu
};

/// Handler of decompiler events.
/// \param ud user data. the value specified at the handler installation time
///           is passed here.
/// \param event decompiler event code
/// \param va additional arguments
/// \return as a rule the callback must return 0 unless specified otherise in the
///         event description.

typedef int idaapi hexrays_cb_t(void *ud, hexrays_event_t event, va_list va);


/// Install handler for decompiler events.
/// \param callback handler to install
/// \param ud user data. this pointer will be passed to your handler by the decompiler.
/// \return false if failed

bool hexapi install_hexrays_callback(hexrays_cb_t *callback, void *ud);

/// Uninstall handler for decompiler events.
/// \param callback handler to uninstall
/// \param ud user data. if NULL, all handler corresponding to \c callback is uninstalled.
///             if not NULL, only the callback instance with the specified \c ud value is uninstalled.
/// \return number of uninstalled handlers.

int hexapi remove_hexrays_callback(hexrays_cb_t *callback, void *ud);



//---------------------------------------------------------------------------
/// \defgroup vdui User interface definitions
//@{

/// Type of the input device.
/// How the user command has been invoked
enum input_device_t
{
  USE_KEYBOARD = 0,     ///< Keyboard
  USE_MOUSE = 1,        ///< Mouse
};
//@}

//---------------------------------------------------------------------------
/// Cursor position in the output text (pseudocode).
struct ctext_position_t
{
  int lnnum;            ///< Line number
  int x;                ///< x coordinate of the cursor within the window
  int y;                ///< y coordinate of the cursor within the window
  /// Is the cursor in the variable/type declaration area?
  /// \param hdrlines Number of lines of the declaration area
  bool in_ctree(int hdrlines) const { return lnnum >= hdrlines; }
  /// Comparison operators
  DECLARE_COMPARISONS(ctext_position_t)
  {
    if ( lnnum < r.lnnum ) return -1;
    if ( lnnum > r.lnnum ) return  1;
    if ( x < r.x ) return -1;
    if ( x > r.x ) return  1;
    return 0;
  }
};

/// Navigation history item.
/// Holds information about interactive decompilation history.
/// Currently this is not saved in the database.
struct history_item_t : public ctext_position_t
{
  ea_t ea;              ///< The entry address of the decompiled function
};

/// Navigation history.
typedef qstack<history_item_t> history_t;

/// Comment types
typedef int cmt_type_t;
const cmt_type_t
  CMT_NONE   = 0x0000,  ///< No comment is possible
  CMT_TAIL   = 0x0001,  ///< Indented comment
  CMT_BLOCK1 = 0x0002,  ///< Anterioir block comment
  CMT_BLOCK2 = 0x0004,  ///< Posterior block comment
  CMT_LVAR   = 0x0008,  ///< Local variable comment
  CMT_FUNC   = 0x0010,  ///< Function comment
  CMT_ALL    = 0x001F;  ///< All comments

//---------------------------------------------------------------------------
/// Information about pseudocode window
struct vdui_t
{
  int flags;            ///< \ref VDUI_
/// \defgroup VDUI_ Properties of pseudocode window
/// Used in vdui_t::flags
//@{
#define VDUI_VISIBLE 0x0001     ///< is visible?
#define VDUI_VALID   0x0002     ///< is valid?
#define VDUI_LOCKED  0x0004     ///< is locked?
//@}

  /// Is the pseudocode window visible?
  /// if not, it might be invisible or destroyed
  bool visible(void) const { return (flags & VDUI_VISIBLE) != 0; }
  /// Does the pseudocode window contain valid code?
  /// It can become invalid if the function type gets changed in IDA.
  bool valid(void) const { return (flags & VDUI_VALID) != 0; }
  /// Does the pseudocode window contain valid code?
  /// We lock windows before modifying them
  bool locked(void) const { return (flags & VDUI_LOCKED) != 0; }
  void set_visible(bool v) { setflag(flags, VDUI_VISIBLE, v); }
  void set_valid(bool v)   { setflag(flags, VDUI_VALID, v); }
  void set_locked(bool v)   { setflag(flags, VDUI_LOCKED, v); }

  int view_idx;         ///< pseudocode window index (0..)
  TWidget *ct;          ///< pseudocode view
  TWidget *toplevel;

  mbl_array_t *mba;     ///< pointer to underlying microcode
  cfuncptr_t cfunc;     ///< pointer to function object
  int last_code;        ///< result of the last micro_request(). See \ref MERR_

  // The folloing fields are valid after get_current_item():
  ctext_position_t cpos;        ///< Current ctext position
  ctree_item_t head;            ///< First ctree item on the current line (for block comments)
  ctree_item_t item;            ///< Current ctree item
  ctree_item_t tail;            ///< Tail ctree item on the current line (for indented comments)

  vdui_t(void);                 // do not create your own vdui_t objects

  /// Refresh pseudocode window.
  /// This is the highest level refresh function.
  /// It causes the most profound refresh possible and can lead to redecompilation
  /// of the current function. Please consider using refresh_ctext()
  /// if you need a more superficial refresh.
  /// \param redo_mba true means to redecompile the current function\n
  ///                 false means to rebuild ctree without regenerating microcode
  /// \sa refresh_ctext()
  void __fastcall hexapi refresh_view(bool redo_mba);

  /// Refresh pseudocode window.
  /// This function refreshes the pseudocode window by regenerating its text
  /// from cfunc_t. Use it after modifying cfunc_t from a plugin.
  /// \sa refresh_view()
  void __fastcall hexapi refresh_ctext(bool activate=true);

  /// Display the specified pseudocode.
  /// This function replaces the pseudocode window contents with the
  /// specified cfunc_t.
  /// \param f pointer to the function to display.
  /// \param activate should the pseudocode window get focus?
  void hexapi switch_to(cfuncptr_t f, bool activate);

  /// Is the current item a statement?
  //// \return false if the cursor is in the local variable/type declaration area\n
  ///          true if the cursor is in the statement area
  bool in_ctree(void) const { return cpos.in_ctree(cfunc->hdrlines); }

  /// Get current number.
  /// If the current item is a number, return pointer to it.
  /// \return NULL if the current item is not a number
  cnumber_t *__fastcall hexapi get_number(void);

  /// Get current label.
  /// If there is a label under the cursor, return its number.
  /// \return -1 if there is no label under the cursor.
  /// prereq: get_current_item() has been called
  int __fastcall hexapi get_current_label(void);

  /// Clear the pseudocode window.
  /// It deletes the current function and microcode.
  void __fastcall hexapi clear(void);

  /// Refresh the current position.
  /// This function refreshes the \ref cpos field.
  /// \return false if failed
  /// \param idv keyboard or mouse
  bool __fastcall hexapi refresh_cpos(input_device_t idv);

  /// Get current item.
  /// This function refreshes the \ref cpos, \ref item, \ref tail fields.
  /// \return false if failed
  /// \param idv keyboard or mouse
  /// \sa cfunc_t::get_line_item()
  bool __fastcall hexapi get_current_item(input_device_t idv);

  /// Rename local variable.
  /// This function displays a dialog box and allows the user to rename a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool __fastcall hexapi ui_rename_lvar(lvar_t *v);

  /// Rename local variable.
  /// This function permanently renames a local variable.
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param name new variable name
  /// \param is_user_name use true to save the new name into the database
  bool __fastcall hexapi rename_lvar(lvar_t *v, const char *name, bool is_user_name);

  /// Set local variable type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool __fastcall hexapi ui_set_lvar_type(lvar_t *v);

  /// Set local variable type.
  /// This function permanently sets a local variable type.
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param type new variable type
  bool __fastcall hexapi set_lvar_type(lvar_t *v, const tinfo_t &type);

  /// Set local variable comment.
  /// This function displays a dialog box and allows the user to edit
  /// the comment of a local variable.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool __fastcall hexapi ui_edit_lvar_cmt(lvar_t *v);

  /// Set local variable comment.
  /// This function permanently sets a variable comment.
  /// \return false if failed
  /// \param v pointer to local variable
  /// \param cmt new comment
  bool __fastcall hexapi set_lvar_cmt(lvar_t *v, const char *cmt);

  /// Map a local variable to another.
  /// This function displays a variable list and allows the user to select mapping.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool __fastcall hexapi ui_map_lvar(lvar_t *v);

  /// Unmap a local variable.
  /// This function displays list of variables mapped to the specified variable
  /// and allows the user to select a variable to unmap.
  /// \return false if failed or cancelled
  /// \param v pointer to local variable
  bool __fastcall hexapi ui_unmap_lvar(lvar_t *v);

  /// Map a local variable to another.
  /// This function permanently maps one lvar to another.
  /// All occurrences of the mapped variable are replaced by the new variable
  /// \return false if failed
  /// \param from the variable being mapped
  /// \param to the variable to map to. if NULL, unmaps the variable
  bool __fastcall hexapi map_lvar(lvar_t *from, lvar_t *to);

  /// Set structure field type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a structure field.
  /// \return false if failed or cancelled
  /// \param sptr pointer to structure
  /// \param mptr pointer to structure member
  bool __fastcall hexapi set_strmem_type(struc_t *sptr, member_t *mptr);

  /// Rename structure field.
  /// This function displays a dialog box and allows the user to rename
  /// a structure field.
  /// \return false if failed or cancelled
  /// \param sptr pointer to structure
  /// \param mptr pointer to structure member
  bool __fastcall hexapi rename_strmem(struc_t *sptr, member_t *mptr);

  /// Set global item type.
  /// This function displays a dialog box and allows the user to change
  /// the type of a global item (data or function).
  /// \return false if failed or cancelled
  /// \param ea address of the global item
  bool __fastcall hexapi set_global_type(ea_t ea);

  /// Rename global item.
  /// This function displays a dialog box and allows the user to rename
  /// a global item (data or function).
  /// \return false if failed or cancelled
  /// \param ea address of the global item
  bool __fastcall hexapi rename_global(ea_t ea);

  /// Rename a label.
  /// This function displays a dialog box and allows the user to rename
  /// a statement label.
  /// \return false if failed or cancelled
  /// \param label label number
  bool __fastcall hexapi rename_label(int label);

  /// Process the Enter key.
  /// This function jumps to the definition of the item under the cursor.
  /// If the current item is a function, it will be decompiled.
  /// If the current item is a global data, its disassemly text will be displayed.
  /// \return false if failed
  /// \param idv what cursor must be used, the keyboard or the mouse
  /// \param OM_NEWWIN: new pseudocode window will open, 0: reuse the existing window
  bool __fastcall hexapi jump_enter(input_device_t idv, int omflags);

  /// Jump to disassembly.
  /// This function jumps to the address in the disassembly window
  /// which corresponds to the current item. The current item is determined
  /// based on the current keyboard cursor position.
  /// \return false if failed
  bool __fastcall hexapi ctree_to_disasm(void);

  /// Check if the specified line can have a comment.
  /// Due to the coordinate system for comments
  /// (http://hexblog.com/2007/08/coordinate_system_for_hexrays.html)
  /// some function lines can not have comments. This function checks if a comment
  /// can be attached to the specified line
  /// \return possible comment types
  /// \param lnnum line number (0 based)
  /// \param cmttype comment types to check
  cmt_type_t __fastcall hexapi calc_cmt_type(size_t lnnum, cmt_type_t cmttype) const;

  /// Edit an indented comment.
  /// This function displays a dialog box and allows the user to edit
  /// the comment for the specified ctree location.
  /// \return false if failed or cancelled
  /// \param loc comment location
  bool __fastcall hexapi edit_cmt(const treeloc_t &loc);

  /// Edit a function comment.
  /// This function displays a dialog box and allows the user to edit
  /// the function comment.
  /// \return false if failed or cancelled
  bool __fastcall hexapi edit_func_cmt(void);

  /// Delete all orphan comments.
  /// Delete all orphan comments and refresh the screen.
  /// \return true
  bool __fastcall hexapi del_orphan_cmts(void);

  /// Change number base.
  /// This function changes the current number representation.
  /// \return false if failed
  /// \param base number radix (10 or 16)\n
  ///             0 means a character constant
  bool __fastcall hexapi set_num_radix(int base);

  /// Convert number to symbolic constant.
  /// This function displays a dialog box and allows the user to select
  /// a symbolic constant to represent the number.
  /// \return false if failed or cancelled
  bool __fastcall hexapi set_num_enum(void);

  /// Convert number to structure field offset.
  /// Currently not implemented.
  /// \return false if failed or cancelled
  bool __fastcall hexapi set_num_stroff(void);

  /// Negate a number.
  /// This function negates the current number.
  /// \return false if failed.
  bool __fastcall hexapi invert_sign(void);

  /// Bitwise negate a number.
  /// This function inverts all bits of the current number.
  /// \return false if failed.
  bool __fastcall hexapi invert_bits(void);

  /// Collapse/uncollapse item.
  /// This function collapses the current item.
  /// \return false if failed.
  bool __fastcall hexapi collapse_item(bool hide);

  /// Collapse/uncollapse local variable declarations.
  /// \return false if failed.
  bool __fastcall hexapi collapse_lvars(bool hide);

  /// Split/unsplit item.
  /// This function splits the current assignment expression.
  /// \return false if failed.
  bool __fastcall hexapi split_item(bool split);

};



//--------------------------------------------------------------------------
// PUBLIC HEX-RAYS API
//--------------------------------------------------------------------------

/// Hex-Rays decompiler dispatcher.
/// All interaction with the decompiler is carried out by the intermediary of this dispatcher.
typedef void *hexdsp_t(int code, ...);

/// Pointer to Hex-Rays decompiler dispatcher.
/// This variable must be instantiated by the plugin. It is initialized by init_hexrays_plugin().
extern hexdsp_t *hexdsp;

/// API call numbers
enum hexcall_t
{
  hx_user_cmts_begin,
  hx_user_cmts_end,
  hx_user_cmts_next,
  hx_user_cmts_prev,
  hx_user_cmts_first,
  hx_user_cmts_second,
  hx_user_cmts_find,
  hx_user_cmts_insert,
  hx_user_cmts_erase,
  hx_user_cmts_clear,
  hx_user_cmts_size,
  hx_user_cmts_free,
  hx_user_numforms_begin,
  hx_user_numforms_end,
  hx_user_numforms_next,
  hx_user_numforms_prev,
  hx_user_numforms_first,
  hx_user_numforms_second,
  hx_user_numforms_find,
  hx_user_numforms_insert,
  hx_user_numforms_erase,
  hx_user_numforms_clear,
  hx_user_numforms_size,
  hx_user_numforms_free,
  hx_user_iflags_begin,
  hx_user_iflags_end,
  hx_user_iflags_next,
  hx_user_iflags_prev,
  hx_user_iflags_first,
  hx_user_iflags_second,
  hx_user_iflags_find,
  hx_user_iflags_insert,
  hx_user_iflags_erase,
  hx_user_iflags_clear,
  hx_user_iflags_size,
  hx_user_iflags_free,
  hx_user_labels_begin,
  hx_user_labels_end,
  hx_user_labels_next,
  hx_user_labels_prev,
  hx_user_labels_first,
  hx_user_labels_second,
  hx_user_labels_find,
  hx_user_labels_insert,
  hx_user_labels_erase,
  hx_user_labels_clear,
  hx_user_labels_size,
  hx_user_labels_free,
  hx_operand_locator_t_compare,
  hx_vd_printer_t_print,
  hx_qstring_printer_t_print,
  hx_remove_typedef,
  hx_is_type_correct,
  hx_is_type_integral,
  hx_is_type_small_struni,
  hx_partial_type_num,
  hx_get_float_bit,
  hx_typestring_print,
  hx_typestring_change_sign,
  hx_typestring_get_cc,
  hx_typestring_get_nth_arg,
  hx_get_int_type_by_width_and_sign,
  hx_get_unk_type,
  hx_get_member_type,
  hx_make_array,
  hx_make_pointer,
  hx_create_typedef,
  hx_remove_pointer,
  hx_cnv_array_to_ptr,
  hx_strtype_info_t_build_base_type,
  hx_strtype_info_t_build_udt_type,
  hx_arglocs_overlap,
  hx_lvar_locator_t_get_regnum,
  hx_lvar_locator_t_compare,
  hx_lvar_t_accepts_type,
  hx_lvar_t_set_lvar_type,
  hx_lvar_t_set_width,
  hx_lvars_t_find_stkvar,
  hx_lvars_t_find,
  hx_lvars_t_find_lvar,
  hx_restore_user_lvar_settings,
  hx_save_user_lvar_settings,
  hx_fnumber_t_print,
  hx_get_hexrays_version,
  hx_open_pseudocode,
  hx_close_pseudocode,
  hx_decompile,
  hx_decompile_many,
  hx_micro_err_format,
  hx_hexrays_failure_t_desc,
  hx_send_database,
  hx_negated_relation,
  hx_get_op_signness,
  hx_asgop,
  hx_asgop_revert,
  hx_cnumber_t_print,
  hx_cnumber_t_value,
  hx_cnumber_t_assign,
  hx_cnumber_t_compare,
  hx_var_ref_t_compare,
  hx_ctree_visitor_t_apply_to,
  hx_ctree_visitor_t_apply_to_exprs,
  hx_ctree_parentee_t_recalc_parent_types,
  hx_cfunc_parentee_t_calc_rvalue_type,
  hx_citem_locator_t_compare,
  hx_citem_t_contains_label,
  hx_citem_t_find_parent_of,
  hx_cexpr_t_assign,
  hx_cexpr_t_compare,
  hx_cexpr_t_replace_by,
  hx_cexpr_t_cleanup,
  hx_cexpr_t_put_number,
  hx_cexpr_t_print1,
  hx_cexpr_t_calc_type,
  hx_cexpr_t_equal_effect,
  hx_cexpr_t_is_child_of,
  hx_cexpr_t_contains_operator,
  hx_cexpr_t_get_high_nbit_bound,
  hx_cexpr_t_requires_lvalue,
  hx_cexpr_t_has_side_effects,
  hx_cif_t_assign,
  hx_cif_t_compare,
  hx_cloop_t_assign,
  hx_cfor_t_compare,
  hx_cwhile_t_compare,
  hx_cdo_t_compare,
  hx_creturn_t_compare,
  hx_cgoto_t_compare,
  hx_casm_t_compare,
  hx_cinsn_t_assign,
  hx_cinsn_t_compare,
  hx_cinsn_t_replace_by,
  hx_cinsn_t_cleanup,
  hx_cinsn_t_new_insn,
  hx_cinsn_t_create_if,
  hx_cinsn_t_print,
  hx_cinsn_t_print1,
  hx_cinsn_t_is_ordinary_flow,
  hx_cinsn_t_contains_insn,
  hx_cinsn_t_collect_free_breaks,
  hx_cinsn_t_collect_free_continues,
  hx_cblock_t_compare,
  hx_carglist_t_compare,
  hx_ccase_t_compare,
  hx_ccases_t_compare,
  hx_cswitch_t_compare,
  hx_ctree_item_t_get_memptr,
  hx_ctree_item_t_get_lvar,
  hx_ctree_item_t_get_ea,
  hx_ctree_item_t_get_label_num,
  hx_lnot,
  hx_new_block,
  hx_vcreate_helper,
  hx_vcall_helper,
  hx_make_num,
  hx_make_ref,
  hx_dereference,
  hx_save_user_labels,
  hx_save_user_cmts,
  hx_save_user_numforms,
  hx_save_user_iflags,
  hx_restore_user_labels,
  hx_restore_user_cmts,
  hx_restore_user_numforms,
  hx_restore_user_iflags,
  hx_cfunc_t_build_c_tree,
  hx_cfunc_t_verify,
  hx_cfunc_t_print_dcl,
  hx_cfunc_t_print_func,
  hx_cfunc_t_get_func_type,
  hx_cfunc_t_get_lvars,
  hx_cfunc_t_find_label,
  hx_cfunc_t_remove_unused_labels,
  hx_cfunc_t_get_user_cmt,
  hx_cfunc_t_set_user_cmt,
  hx_cfunc_t_get_user_iflags,
  hx_cfunc_t_set_user_iflags,
  hx_cfunc_t_has_orphan_cmts,
  hx_cfunc_t_del_orphan_cmts,
  hx_cfunc_t_get_line_item,
  hx_cfunc_t_get_warnings,
  hx_cfunc_t_gather_derefs,
  hx_cfunc_t_cleanup,
  hx_get_ctype_name,
  hx_install_hexrays_callback,
  hx_remove_hexrays_callback,
  hx_vdui_t_refresh_view,
  hx_vdui_t_refresh_ctext,
  hx_vdui_t_switch_to,
  hx_vdui_t_get_number,
  hx_vdui_t_clear,
  hx_vdui_t_refresh_cpos,
  hx_vdui_t_get_current_item,
  hx_vdui_t_ui_rename_lvar,
  hx_vdui_t_rename_lvar,
  hx_vdui_t_ui_set_lvar_type,
  hx_vdui_t_set_lvar_type,
  hx_vdui_t_edit_lvar_cmt,
  hx_vdui_t_set_lvar_cmt,
  hx_vdui_t_set_strmem_type,
  hx_vdui_t_rename_strmem,
  hx_vdui_t_set_global_type,
  hx_vdui_t_rename_global,
  hx_vdui_t_rename_label,
  hx_vdui_t_jump_enter,
  hx_vdui_t_ctree_to_disasm,
  hx_vdui_t_push_current_location,
  hx_vdui_t_pop_current_location,
  hx_vdui_t_calc_cmt_type,
  hx_vdui_t_edit_cmt,
  hx_vdui_t_edit_func_cmt,
  hx_vdui_t_del_orphan_cmts,
  hx_vdui_t_set_num_radix,
  hx_vdui_t_set_num_enum,
  hx_vdui_t_set_num_stroff,
  hx_vdui_t_invert_sign,
  hx_vdui_t_collapse_item,
  hx_vdui_t_split_item,
  hx_vdui_t_set_vargloc_end,
  hx_lvar_mapping_begin,
  hx_lvar_mapping_end,
  hx_lvar_mapping_next,
  hx_lvar_mapping_prev,
  hx_lvar_mapping_first,
  hx_lvar_mapping_second,
  hx_lvar_mapping_find,
  hx_lvar_mapping_insert,
  hx_lvar_mapping_erase,
  hx_lvar_mapping_clear,
  hx_lvar_mapping_size,
  hx_lvar_mapping_free,
  hx_user_unions_begin,
  hx_user_unions_end,
  hx_user_unions_next,
  hx_user_unions_prev,
  hx_user_unions_first,
  hx_user_unions_second,
  hx_user_unions_find,
  hx_user_unions_insert,
  hx_user_unions_erase,
  hx_user_unions_clear,
  hx_user_unions_size,
  hx_user_unions_free,
  hx_strtype_info_t_create_from,
  hx_save_user_unions,
  hx_restore_user_unions,
  hx_cfunc_t_get_user_union_selection,
  hx_cfunc_t_set_user_union_selection,
  hx_vdui_t_ui_edit_lvar_cmt,
  hx_vdui_t_ui_map_lvar,
  hx_vdui_t_ui_unmap_lvar,
  hx_vdui_t_map_lvar,
  hx_dummy_ptrtype,
  hx_create_field_name,
  hx_dummy_plist_for,
  hx_make_dt,
  hx_cexpr_t_get_low_nbit_bound,
  hx_eamap_begin,
  hx_eamap_end,
  hx_eamap_next,
  hx_eamap_prev,
  hx_eamap_first,
  hx_eamap_second,
  hx_eamap_find,
  hx_eamap_insert,
  hx_eamap_erase,
  hx_eamap_clear,
  hx_eamap_size,
  hx_eamap_free,
  hx_boundaries_begin,
  hx_boundaries_end,
  hx_boundaries_next,
  hx_boundaries_prev,
  hx_boundaries_first,
  hx_boundaries_second,
  hx_boundaries_find,
  hx_boundaries_insert,
  hx_boundaries_erase,
  hx_boundaries_clear,
  hx_boundaries_size,
  hx_boundaries_free,
  hx_mark_cfunc_dirty,
  hx_clear_cached_cfuncs,
  hx_has_cached_cfunc,
  hx_cfunc_t_get_eamap,
  hx_cfunc_t_get_boundaries,
  hx_cfunc_t_get_pseudocode,
  hx_vdui_t_collapse_lvars,
  hx_vdui_t_invert_bits,
  hx_print_vdloc,
  hx_is_small_struni,
  hx_is_nonbool_type,
  hx_is_bool_type,
  hx_get_type,
  hx_set_type,
  hx_vdloc_t_compare,
  hx_get_float_type,
  hx_vdui_t_get_current_label,
  hx_get_widget_vdui,
  hx_cfunc_t_print_dcl2,
  hx_modify_user_lvars,
  hx_user_numforms_new,
  hx_lvar_mapping_new,
  hx_user_cmts_new,
  hx_user_iflags_new,
  hx_user_unions_new,
  hx_user_labels_new,
  hx_eamap_new,
  hx_boundaries_new,
  hx_restore_user_defined_calls,
  hx_save_user_defined_calls,
  hx_udcall_map_begin,
  hx_udcall_map_end,
  hx_udcall_map_next,
  hx_udcall_map_prev,
  hx_udcall_map_first,
  hx_udcall_map_second,
  hx_udcall_map_find,
  hx_udcall_map_insert,
  hx_udcall_map_erase,
  hx_udcall_map_clear,
  hx_udcall_map_size,
  hx_udcall_map_free,
  hx_udcall_map_new,
  hx_parse_user_call,
  hx_convert_to_user_call,
  hx_install_microcode_filter,
  hx_microcode_filter_t_match,
  hx_microcode_filter_t_apply,
  hx_udc_filter_t_apply,
  hx_udc_filter_t_match,
  hx_udc_filter_t_init,
  hx_cfunc_t_get_stkoff_delta,
};

typedef size_t iterator_word;

//--------------------------------------------------------------------------
/// Initialize your plugin for hex-rays decompiler.
/// This function must be called before calling any other decompiler function.
/// It initializes the pointer to the dispatcher.
/// \param flags reserved, must be 0
/// \return true if the decompiler exists and the dispatcher pointer is ready to use.
inline bool init_hexrays_plugin(int flags=0)
{
  return callui(ui_broadcast, HEXRAYS_API_MAGIC, &hexdsp, flags).i == (HEXRAYS_API_MAGIC >> 32);
}

//--------------------------------------------------------------------------
/// Terminate your plugin for hex-rays decompiler.
/// Currently this function is empty but please do include it in your plugins.
inline void term_hexrays_plugin(void)
{
}

//-------------------------------------------------------------------------
struct user_numforms_iterator_t
{
  iterator_word x;
  bool operator==(const user_numforms_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_numforms_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_numforms_t
inline user_numforms_iterator_t user_numforms_begin(const user_numforms_t *map)
{
  user_numforms_iterator_t p;
  hexdsp(hx_user_numforms_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_numforms_t
inline user_numforms_iterator_t user_numforms_end(const user_numforms_t *map)
{
  user_numforms_iterator_t p;
  hexdsp(hx_user_numforms_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_numforms_iterator_t user_numforms_next(user_numforms_iterator_t p)
{
  hexdsp(hx_user_numforms_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_numforms_iterator_t user_numforms_prev(user_numforms_iterator_t p)
{
  hexdsp(hx_user_numforms_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline operand_locator_t const &user_numforms_first(user_numforms_iterator_t p)
{
  return *(operand_locator_t *)hexdsp(hx_user_numforms_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline number_format_t &user_numforms_second(user_numforms_iterator_t p)
{
  return *(number_format_t *)hexdsp(hx_user_numforms_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_numforms_t
inline user_numforms_iterator_t user_numforms_find(const user_numforms_t *map, const operand_locator_t &key)
{
  user_numforms_iterator_t p;
  hexdsp(hx_user_numforms_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (operand_locator_t, number_format_t) pair into user_numforms_t
inline user_numforms_iterator_t user_numforms_insert(user_numforms_t *map, const operand_locator_t &key, const number_format_t &val)
{
  user_numforms_iterator_t p;
  hexdsp(hx_user_numforms_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_numforms_t
inline void user_numforms_erase(user_numforms_t *map, user_numforms_iterator_t p)
{
  hexdsp(hx_user_numforms_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_numforms_t
inline void user_numforms_clear(user_numforms_t *map)
{
  hexdsp(hx_user_numforms_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_numforms_t
inline size_t user_numforms_size(user_numforms_t *map)
{
  return (size_t)hexdsp(hx_user_numforms_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_numforms_t instance
inline void user_numforms_free(user_numforms_t *map)
{
  hexdsp(hx_user_numforms_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_numforms_t instance
inline user_numforms_t *user_numforms_new(void)
{
  return (user_numforms_t *)hexdsp(hx_user_numforms_new);
}

//-------------------------------------------------------------------------
struct lvar_mapping_iterator_t
{
  iterator_word x;
  bool operator==(const lvar_mapping_iterator_t &p) const { return x == p.x; }
  bool operator!=(const lvar_mapping_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_begin(const lvar_mapping_t *map)
{
  lvar_mapping_iterator_t p;
  hexdsp(hx_lvar_mapping_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_end(const lvar_mapping_t *map)
{
  lvar_mapping_iterator_t p;
  hexdsp(hx_lvar_mapping_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline lvar_mapping_iterator_t lvar_mapping_next(lvar_mapping_iterator_t p)
{
  hexdsp(hx_lvar_mapping_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline lvar_mapping_iterator_t lvar_mapping_prev(lvar_mapping_iterator_t p)
{
  hexdsp(hx_lvar_mapping_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline lvar_locator_t const &lvar_mapping_first(lvar_mapping_iterator_t p)
{
  return *(lvar_locator_t *)hexdsp(hx_lvar_mapping_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline lvar_locator_t &lvar_mapping_second(lvar_mapping_iterator_t p)
{
  return *(lvar_locator_t *)hexdsp(hx_lvar_mapping_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_find(const lvar_mapping_t *map, const lvar_locator_t &key)
{
  lvar_mapping_iterator_t p;
  hexdsp(hx_lvar_mapping_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (lvar_locator_t, lvar_locator_t) pair into lvar_mapping_t
inline lvar_mapping_iterator_t lvar_mapping_insert(lvar_mapping_t *map, const lvar_locator_t &key, const lvar_locator_t &val)
{
  lvar_mapping_iterator_t p;
  hexdsp(hx_lvar_mapping_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from lvar_mapping_t
inline void lvar_mapping_erase(lvar_mapping_t *map, lvar_mapping_iterator_t p)
{
  hexdsp(hx_lvar_mapping_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear lvar_mapping_t
inline void lvar_mapping_clear(lvar_mapping_t *map)
{
  hexdsp(hx_lvar_mapping_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of lvar_mapping_t
inline size_t lvar_mapping_size(lvar_mapping_t *map)
{
  return (size_t)hexdsp(hx_lvar_mapping_size, map);
}

//-------------------------------------------------------------------------
/// Delete lvar_mapping_t instance
inline void lvar_mapping_free(lvar_mapping_t *map)
{
  hexdsp(hx_lvar_mapping_free, map);
}

//-------------------------------------------------------------------------
/// Create a new lvar_mapping_t instance
inline lvar_mapping_t *lvar_mapping_new(void)
{
  return (lvar_mapping_t *)hexdsp(hx_lvar_mapping_new);
}

//-------------------------------------------------------------------------
struct udcall_map_iterator_t
{
  iterator_word x;
  bool operator==(const udcall_map_iterator_t &p) const { return x == p.x; }
  bool operator!=(const udcall_map_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of udcall_map_t
inline udcall_map_iterator_t udcall_map_begin(const udcall_map_t *map)
{
  udcall_map_iterator_t p;
  hexdsp(hx_udcall_map_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of udcall_map_t
inline udcall_map_iterator_t udcall_map_end(const udcall_map_t *map)
{
  udcall_map_iterator_t p;
  hexdsp(hx_udcall_map_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline udcall_map_iterator_t udcall_map_next(udcall_map_iterator_t p)
{
  hexdsp(hx_udcall_map_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline udcall_map_iterator_t udcall_map_prev(udcall_map_iterator_t p)
{
  hexdsp(hx_udcall_map_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &udcall_map_first(udcall_map_iterator_t p)
{
  return *(ea_t *)hexdsp(hx_udcall_map_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline udcall_t &udcall_map_second(udcall_map_iterator_t p)
{
  return *(udcall_t *)hexdsp(hx_udcall_map_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in udcall_map_t
inline udcall_map_iterator_t udcall_map_find(const udcall_map_t *map, const ea_t &key)
{
  udcall_map_iterator_t p;
  hexdsp(hx_udcall_map_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, udcall_t) pair into udcall_map_t
inline udcall_map_iterator_t udcall_map_insert(udcall_map_t *map, const ea_t &key, const udcall_t &val)
{
  udcall_map_iterator_t p;
  hexdsp(hx_udcall_map_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from udcall_map_t
inline void udcall_map_erase(udcall_map_t *map, udcall_map_iterator_t p)
{
  hexdsp(hx_udcall_map_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear udcall_map_t
inline void udcall_map_clear(udcall_map_t *map)
{
  hexdsp(hx_udcall_map_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of udcall_map_t
inline size_t udcall_map_size(udcall_map_t *map)
{
  return (size_t)hexdsp(hx_udcall_map_size, map);
}

//-------------------------------------------------------------------------
/// Delete udcall_map_t instance
inline void udcall_map_free(udcall_map_t *map)
{
  hexdsp(hx_udcall_map_free, map);
}

//-------------------------------------------------------------------------
/// Create a new udcall_map_t instance
inline udcall_map_t *udcall_map_new(void)
{
  return (udcall_map_t *)hexdsp(hx_udcall_map_new);
}

//-------------------------------------------------------------------------
struct user_cmts_iterator_t
{
  iterator_word x;
  bool operator==(const user_cmts_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_cmts_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_cmts_t
inline user_cmts_iterator_t user_cmts_begin(const user_cmts_t *map)
{
  user_cmts_iterator_t p;
  hexdsp(hx_user_cmts_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_cmts_t
inline user_cmts_iterator_t user_cmts_end(const user_cmts_t *map)
{
  user_cmts_iterator_t p;
  hexdsp(hx_user_cmts_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_cmts_iterator_t user_cmts_next(user_cmts_iterator_t p)
{
  hexdsp(hx_user_cmts_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_cmts_iterator_t user_cmts_prev(user_cmts_iterator_t p)
{
  hexdsp(hx_user_cmts_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline treeloc_t const &user_cmts_first(user_cmts_iterator_t p)
{
  return *(treeloc_t *)hexdsp(hx_user_cmts_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline citem_cmt_t &user_cmts_second(user_cmts_iterator_t p)
{
  return *(citem_cmt_t *)hexdsp(hx_user_cmts_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_cmts_t
inline user_cmts_iterator_t user_cmts_find(const user_cmts_t *map, const treeloc_t &key)
{
  user_cmts_iterator_t p;
  hexdsp(hx_user_cmts_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (treeloc_t, citem_cmt_t) pair into user_cmts_t
inline user_cmts_iterator_t user_cmts_insert(user_cmts_t *map, const treeloc_t &key, const citem_cmt_t &val)
{
  user_cmts_iterator_t p;
  hexdsp(hx_user_cmts_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_cmts_t
inline void user_cmts_erase(user_cmts_t *map, user_cmts_iterator_t p)
{
  hexdsp(hx_user_cmts_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_cmts_t
inline void user_cmts_clear(user_cmts_t *map)
{
  hexdsp(hx_user_cmts_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_cmts_t
inline size_t user_cmts_size(user_cmts_t *map)
{
  return (size_t)hexdsp(hx_user_cmts_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_cmts_t instance
inline void user_cmts_free(user_cmts_t *map)
{
  hexdsp(hx_user_cmts_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_cmts_t instance
inline user_cmts_t *user_cmts_new(void)
{
  return (user_cmts_t *)hexdsp(hx_user_cmts_new);
}

//-------------------------------------------------------------------------
struct user_iflags_iterator_t
{
  iterator_word x;
  bool operator==(const user_iflags_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_iflags_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_iflags_t
inline user_iflags_iterator_t user_iflags_begin(const user_iflags_t *map)
{
  user_iflags_iterator_t p;
  hexdsp(hx_user_iflags_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_iflags_t
inline user_iflags_iterator_t user_iflags_end(const user_iflags_t *map)
{
  user_iflags_iterator_t p;
  hexdsp(hx_user_iflags_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_iflags_iterator_t user_iflags_next(user_iflags_iterator_t p)
{
  hexdsp(hx_user_iflags_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_iflags_iterator_t user_iflags_prev(user_iflags_iterator_t p)
{
  hexdsp(hx_user_iflags_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline citem_locator_t const &user_iflags_first(user_iflags_iterator_t p)
{
  return *(citem_locator_t *)hexdsp(hx_user_iflags_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline int32 &user_iflags_second(user_iflags_iterator_t p)
{
  return *(int32 *)hexdsp(hx_user_iflags_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_iflags_t
inline user_iflags_iterator_t user_iflags_find(const user_iflags_t *map, const citem_locator_t &key)
{
  user_iflags_iterator_t p;
  hexdsp(hx_user_iflags_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (citem_locator_t, int32) pair into user_iflags_t
inline user_iflags_iterator_t user_iflags_insert(user_iflags_t *map, const citem_locator_t &key, const int32 &val)
{
  user_iflags_iterator_t p;
  hexdsp(hx_user_iflags_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_iflags_t
inline void user_iflags_erase(user_iflags_t *map, user_iflags_iterator_t p)
{
  hexdsp(hx_user_iflags_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_iflags_t
inline void user_iflags_clear(user_iflags_t *map)
{
  hexdsp(hx_user_iflags_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_iflags_t
inline size_t user_iflags_size(user_iflags_t *map)
{
  return (size_t)hexdsp(hx_user_iflags_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_iflags_t instance
inline void user_iflags_free(user_iflags_t *map)
{
  hexdsp(hx_user_iflags_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_iflags_t instance
inline user_iflags_t *user_iflags_new(void)
{
  return (user_iflags_t *)hexdsp(hx_user_iflags_new);
}

//-------------------------------------------------------------------------
struct user_unions_iterator_t
{
  iterator_word x;
  bool operator==(const user_unions_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_unions_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_unions_t
inline user_unions_iterator_t user_unions_begin(const user_unions_t *map)
{
  user_unions_iterator_t p;
  hexdsp(hx_user_unions_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_unions_t
inline user_unions_iterator_t user_unions_end(const user_unions_t *map)
{
  user_unions_iterator_t p;
  hexdsp(hx_user_unions_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_unions_iterator_t user_unions_next(user_unions_iterator_t p)
{
  hexdsp(hx_user_unions_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_unions_iterator_t user_unions_prev(user_unions_iterator_t p)
{
  hexdsp(hx_user_unions_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &user_unions_first(user_unions_iterator_t p)
{
  return *(ea_t *)hexdsp(hx_user_unions_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline intvec_t &user_unions_second(user_unions_iterator_t p)
{
  return *(intvec_t *)hexdsp(hx_user_unions_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_unions_t
inline user_unions_iterator_t user_unions_find(const user_unions_t *map, const ea_t &key)
{
  user_unions_iterator_t p;
  hexdsp(hx_user_unions_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, intvec_t) pair into user_unions_t
inline user_unions_iterator_t user_unions_insert(user_unions_t *map, const ea_t &key, const intvec_t &val)
{
  user_unions_iterator_t p;
  hexdsp(hx_user_unions_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_unions_t
inline void user_unions_erase(user_unions_t *map, user_unions_iterator_t p)
{
  hexdsp(hx_user_unions_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_unions_t
inline void user_unions_clear(user_unions_t *map)
{
  hexdsp(hx_user_unions_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_unions_t
inline size_t user_unions_size(user_unions_t *map)
{
  return (size_t)hexdsp(hx_user_unions_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_unions_t instance
inline void user_unions_free(user_unions_t *map)
{
  hexdsp(hx_user_unions_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_unions_t instance
inline user_unions_t *user_unions_new(void)
{
  return (user_unions_t *)hexdsp(hx_user_unions_new);
}

//-------------------------------------------------------------------------
struct user_labels_iterator_t
{
  iterator_word x;
  bool operator==(const user_labels_iterator_t &p) const { return x == p.x; }
  bool operator!=(const user_labels_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of user_labels_t
inline user_labels_iterator_t user_labels_begin(const user_labels_t *map)
{
  user_labels_iterator_t p;
  hexdsp(hx_user_labels_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of user_labels_t
inline user_labels_iterator_t user_labels_end(const user_labels_t *map)
{
  user_labels_iterator_t p;
  hexdsp(hx_user_labels_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline user_labels_iterator_t user_labels_next(user_labels_iterator_t p)
{
  hexdsp(hx_user_labels_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline user_labels_iterator_t user_labels_prev(user_labels_iterator_t p)
{
  hexdsp(hx_user_labels_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline int const &user_labels_first(user_labels_iterator_t p)
{
  return *(int *)hexdsp(hx_user_labels_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline qstring &user_labels_second(user_labels_iterator_t p)
{
  return *(qstring *)hexdsp(hx_user_labels_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in user_labels_t
inline user_labels_iterator_t user_labels_find(const user_labels_t *map, const int &key)
{
  user_labels_iterator_t p;
  hexdsp(hx_user_labels_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (int, qstring) pair into user_labels_t
inline user_labels_iterator_t user_labels_insert(user_labels_t *map, const int &key, const qstring &val)
{
  user_labels_iterator_t p;
  hexdsp(hx_user_labels_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from user_labels_t
inline void user_labels_erase(user_labels_t *map, user_labels_iterator_t p)
{
  hexdsp(hx_user_labels_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear user_labels_t
inline void user_labels_clear(user_labels_t *map)
{
  hexdsp(hx_user_labels_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of user_labels_t
inline size_t user_labels_size(user_labels_t *map)
{
  return (size_t)hexdsp(hx_user_labels_size, map);
}

//-------------------------------------------------------------------------
/// Delete user_labels_t instance
inline void user_labels_free(user_labels_t *map)
{
  hexdsp(hx_user_labels_free, map);
}

//-------------------------------------------------------------------------
/// Create a new user_labels_t instance
inline user_labels_t *user_labels_new(void)
{
  return (user_labels_t *)hexdsp(hx_user_labels_new);
}

//-------------------------------------------------------------------------
struct eamap_iterator_t
{
  iterator_word x;
  bool operator==(const eamap_iterator_t &p) const { return x == p.x; }
  bool operator!=(const eamap_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of eamap_t
inline eamap_iterator_t eamap_begin(const eamap_t *map)
{
  eamap_iterator_t p;
  hexdsp(hx_eamap_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of eamap_t
inline eamap_iterator_t eamap_end(const eamap_t *map)
{
  eamap_iterator_t p;
  hexdsp(hx_eamap_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline eamap_iterator_t eamap_next(eamap_iterator_t p)
{
  hexdsp(hx_eamap_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline eamap_iterator_t eamap_prev(eamap_iterator_t p)
{
  hexdsp(hx_eamap_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline ea_t const &eamap_first(eamap_iterator_t p)
{
  return *(ea_t *)hexdsp(hx_eamap_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline cinsnptrvec_t &eamap_second(eamap_iterator_t p)
{
  return *(cinsnptrvec_t *)hexdsp(hx_eamap_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in eamap_t
inline eamap_iterator_t eamap_find(const eamap_t *map, const ea_t &key)
{
  eamap_iterator_t p;
  hexdsp(hx_eamap_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (ea_t, cinsnptrvec_t) pair into eamap_t
inline eamap_iterator_t eamap_insert(eamap_t *map, const ea_t &key, const cinsnptrvec_t &val)
{
  eamap_iterator_t p;
  hexdsp(hx_eamap_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from eamap_t
inline void eamap_erase(eamap_t *map, eamap_iterator_t p)
{
  hexdsp(hx_eamap_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear eamap_t
inline void eamap_clear(eamap_t *map)
{
  hexdsp(hx_eamap_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of eamap_t
inline size_t eamap_size(eamap_t *map)
{
  return (size_t)hexdsp(hx_eamap_size, map);
}

//-------------------------------------------------------------------------
/// Delete eamap_t instance
inline void eamap_free(eamap_t *map)
{
  hexdsp(hx_eamap_free, map);
}

//-------------------------------------------------------------------------
/// Create a new eamap_t instance
inline eamap_t *eamap_new(void)
{
  return (eamap_t *)hexdsp(hx_eamap_new);
}

//-------------------------------------------------------------------------
struct boundaries_iterator_t
{
  iterator_word x;
  bool operator==(const boundaries_iterator_t &p) const { return x == p.x; }
  bool operator!=(const boundaries_iterator_t &p) const { return x != p.x; }
};

//-------------------------------------------------------------------------
/// Get iterator pointing to the beginning of boundaries_t
inline boundaries_iterator_t boundaries_begin(const boundaries_t *map)
{
  boundaries_iterator_t p;
  hexdsp(hx_boundaries_begin, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Get iterator pointing to the end of boundaries_t
inline boundaries_iterator_t boundaries_end(const boundaries_t *map)
{
  boundaries_iterator_t p;
  hexdsp(hx_boundaries_end, &p, map);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the next element
inline boundaries_iterator_t boundaries_next(boundaries_iterator_t p)
{
  hexdsp(hx_boundaries_next, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Move to the previous element
inline boundaries_iterator_t boundaries_prev(boundaries_iterator_t p)
{
  hexdsp(hx_boundaries_prev, &p);
  return p;
}

//-------------------------------------------------------------------------
/// Get reference to the current map key
inline cinsn_t *const &boundaries_first(boundaries_iterator_t p)
{
  return *(cinsn_t * *)hexdsp(hx_boundaries_first, &p);
}

//-------------------------------------------------------------------------
/// Get reference to the current map value
inline rangeset_t &boundaries_second(boundaries_iterator_t p)
{
  return *(rangeset_t *)hexdsp(hx_boundaries_second, &p);
}

//-------------------------------------------------------------------------
/// Find the specified key in boundaries_t
inline boundaries_iterator_t boundaries_find(const boundaries_t *map, const cinsn_t * &key)
{
  boundaries_iterator_t p;
  hexdsp(hx_boundaries_find, &p, map, &key);
  return p;
}

//-------------------------------------------------------------------------
/// Insert new (cinsn_t *, rangeset_t) pair into boundaries_t
inline boundaries_iterator_t boundaries_insert(boundaries_t *map, const cinsn_t * &key, const rangeset_t &val)
{
  boundaries_iterator_t p;
  hexdsp(hx_boundaries_insert, &p, map, &key, &val);
  return p;
}

//-------------------------------------------------------------------------
/// Erase current element from boundaries_t
inline void boundaries_erase(boundaries_t *map, boundaries_iterator_t p)
{
  hexdsp(hx_boundaries_erase, map, &p);
}

//-------------------------------------------------------------------------
/// Clear boundaries_t
inline void boundaries_clear(boundaries_t *map)
{
  hexdsp(hx_boundaries_clear, map);
}

//-------------------------------------------------------------------------
/// Get size of boundaries_t
inline size_t boundaries_size(boundaries_t *map)
{
  return (size_t)hexdsp(hx_boundaries_size, map);
}

//-------------------------------------------------------------------------
/// Delete boundaries_t instance
inline void boundaries_free(boundaries_t *map)
{
  hexdsp(hx_boundaries_free, map);
}

//-------------------------------------------------------------------------
/// Create a new boundaries_t instance
inline boundaries_t *boundaries_new(void)
{
  return (boundaries_t *)hexdsp(hx_boundaries_new);
}

//--------------------------------------------------------------------------
inline int operand_locator_t::compare(const operand_locator_t &r) const
{
  return (int)(size_t)hexdsp(hx_operand_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 4) int vd_printer_t::print(int indent, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int retval = (int)(size_t)hexdsp(hx_vd_printer_t_print, this, indent, format, va);
  va_end(va);
  return retval;
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 4) int qstring_printer_t::print(int indent, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int retval = (int)(size_t)hexdsp(hx_qstring_printer_t_print, this, indent, format, va);
  va_end(va);
  return retval;
}

//--------------------------------------------------------------------------
inline bool is_type_correct(const type_t *ptr)
{
  return (uchar)(size_t)hexdsp(hx_is_type_correct, ptr) != 0;
}

//--------------------------------------------------------------------------
inline bool is_small_struni(const tinfo_t &tif)
{
  return (uchar)(size_t)hexdsp(hx_is_small_struni, &tif) != 0;
}

//--------------------------------------------------------------------------
inline bool is_nonbool_type(const tinfo_t &type)
{
  return (uchar)(size_t)hexdsp(hx_is_nonbool_type, &type) != 0;
}

//--------------------------------------------------------------------------
inline bool is_bool_type(const tinfo_t &type)
{
  return (uchar)(size_t)hexdsp(hx_is_bool_type, &type) != 0;
}

//--------------------------------------------------------------------------
inline int partial_type_num(const tinfo_t &type)
{
  return (int)(size_t)hexdsp(hx_partial_type_num, &type);
}

//--------------------------------------------------------------------------
inline tinfo_t get_float_type(int width)
{
  tinfo_t retval;
  hexdsp(hx_get_float_type, &retval, width);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t get_int_type_by_width_and_sign(int srcwidth, type_sign_t sign)
{
  tinfo_t retval;
  hexdsp(hx_get_int_type_by_width_and_sign, &retval, srcwidth, sign);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t get_unk_type(int size)
{
  tinfo_t retval;
  hexdsp(hx_get_unk_type, &retval, size);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t dummy_ptrtype(int ptrsize, bool isfp)
{
  tinfo_t retval;
  hexdsp(hx_dummy_ptrtype, &retval, ptrsize, isfp);
  return retval;
}

//--------------------------------------------------------------------------
inline bool get_member_type(const member_t *mptr, tinfo_t *type)
{
  return (uchar)(size_t)hexdsp(hx_get_member_type, mptr, type) != 0;
}

//--------------------------------------------------------------------------
inline tinfo_t make_pointer(const tinfo_t &type)
{
  tinfo_t retval;
  hexdsp(hx_make_pointer, &retval, &type);
  return retval;
}

//--------------------------------------------------------------------------
inline tinfo_t create_typedef(const char *name)
{
  tinfo_t retval;
  hexdsp(hx_create_typedef, &retval, name);
  return retval;
}

//--------------------------------------------------------------------------
inline bool get_type(uval_t id, tinfo_t *tif, type_source_t guess)
{
  return (uchar)(size_t)hexdsp(hx_get_type, &id, tif, guess) != 0;
}

//--------------------------------------------------------------------------
inline bool set_type(uval_t id, const tinfo_t &tif, type_source_t source, bool force)
{
  return (uchar)(size_t)hexdsp(hx_set_type, &id, &tif, source, force) != 0;
}

//--------------------------------------------------------------------------
inline size_t print_vdloc(char *buf, size_t bufsize, const vdloc_t &loc, int w)
{
  return (size_t)hexdsp(hx_print_vdloc, buf, bufsize, &loc, w);
}

//--------------------------------------------------------------------------
inline bool arglocs_overlap(const vdloc_t &loc1, size_t w1, const vdloc_t &loc2, size_t w2)
{
  return (uchar)(size_t)hexdsp(hx_arglocs_overlap, &loc1, w1, &loc2, w2) != 0;
}

//--------------------------------------------------------------------------
inline sval_t lvar_locator_t::get_regnum(void) const
{
  sval_t retval;
  hexdsp(hx_lvar_locator_t_get_regnum, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline int lvar_locator_t::compare(const lvar_locator_t &r) const
{
  return (int)(size_t)hexdsp(hx_lvar_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool lvar_t::accepts_type(const tinfo_t &t)
{
  return (uchar)(size_t)hexdsp(hx_lvar_t_accepts_type, this, &t) != 0;
}

//--------------------------------------------------------------------------
inline bool lvar_t::set_lvar_type(const tinfo_t &t, bool may_fail)
{
  return (uchar)(size_t)hexdsp(hx_lvar_t_set_lvar_type, this, &t, may_fail) != 0;
}

//--------------------------------------------------------------------------
inline bool lvar_t::set_width(int w, int svw_flags)
{
  return (uchar)(size_t)hexdsp(hx_lvar_t_set_width, this, w, svw_flags) != 0;
}

//--------------------------------------------------------------------------
inline int lvars_t::find_stkvar(int32 spoff, int width)
{
  return (int)(size_t)hexdsp(hx_lvars_t_find_stkvar, this, spoff, width);
}

//--------------------------------------------------------------------------
inline lvar_t *lvars_t::find(const lvar_locator_t &ll)
{
  return (lvar_t *)hexdsp(hx_lvars_t_find, this, &ll);
}

//--------------------------------------------------------------------------
inline int lvars_t::find_lvar(const vdloc_t &location, int width, int defblk)
{
  return (int)(size_t)hexdsp(hx_lvars_t_find_lvar, this, &location, width, defblk);
}

//--------------------------------------------------------------------------
inline bool restore_user_lvar_settings(lvar_uservec_t *lvinf, ea_t func_ea)
{
  return (uchar)(size_t)hexdsp(hx_restore_user_lvar_settings, lvinf, &func_ea) != 0;
}

//--------------------------------------------------------------------------
inline void save_user_lvar_settings(ea_t func_ea, const lvar_uservec_t &lvinf)
{
  hexdsp(hx_save_user_lvar_settings, &func_ea, &lvinf);
}

//--------------------------------------------------------------------------
inline bool modify_user_lvars(ea_t entry_ea, user_lvar_modifier_t &mlv)
{
  return (uchar)(size_t)hexdsp(hx_modify_user_lvars, &entry_ea, &mlv) != 0;
}

//--------------------------------------------------------------------------
inline bool restore_user_defined_calls(udcall_map_t *udcalls, ea_t func_ea)
{
  return (uchar)(size_t)hexdsp(hx_restore_user_defined_calls, udcalls, &func_ea) != 0;
}

//--------------------------------------------------------------------------
inline void save_user_defined_calls(ea_t func_ea, const udcall_map_t &udcalls)
{
  hexdsp(hx_save_user_defined_calls, &func_ea, &udcalls);
}

//--------------------------------------------------------------------------
inline bool parse_user_call(udcall_t *udc, const char *decl, bool silent)
{
  return (uchar)(size_t)hexdsp(hx_parse_user_call, udc, decl, silent) != 0;
}

//--------------------------------------------------------------------------
inline int convert_to_user_call(const udcall_t &udc, codegen_t &cdg)
{
  return (int)(size_t)hexdsp(hx_convert_to_user_call, &udc, &cdg);
}

//--------------------------------------------------------------------------
inline void install_microcode_filter(microcode_filter_t *filter, bool install)
{
  hexdsp(hx_install_microcode_filter, filter, install);
}

//--------------------------------------------------------------------------
inline bool udc_filter_t::init(const char *decl)
{
  return (uchar)(size_t)hexdsp(hx_udc_filter_t_init, this, decl) != 0;
}

//--------------------------------------------------------------------------
inline int udc_filter_t::apply(codegen_t &cdg)
{
  return (int)(size_t)hexdsp(hx_udc_filter_t_apply, this, &cdg);
}

//--------------------------------------------------------------------------
inline size_t fnumber_t::print(char *buf, size_t bufsize) const
{
  return (size_t)hexdsp(hx_fnumber_t_print, this, buf, bufsize);
}

//--------------------------------------------------------------------------
inline const char *get_hexrays_version(void)
{
  return (const char *)hexdsp(hx_get_hexrays_version);
}

//--------------------------------------------------------------------------
inline vdui_t *open_pseudocode(ea_t ea, int new_window)
{
  return (vdui_t *)hexdsp(hx_open_pseudocode, &ea, new_window);
}

//--------------------------------------------------------------------------
inline bool close_pseudocode(TWidget *f)
{
  return (uchar)(size_t)hexdsp(hx_close_pseudocode, f) != 0;
}

//--------------------------------------------------------------------------
inline vdui_t *get_widget_vdui(TWidget *f)
{
  return (vdui_t *)hexdsp(hx_get_widget_vdui, f);
}

//--------------------------------------------------------------------------
inline bool decompile_many(const char *outfile, eavec_t *funcaddrs, int flags)
{
  return (uchar)(size_t)hexdsp(hx_decompile_many, outfile, funcaddrs, flags) != 0;
}

//--------------------------------------------------------------------------
inline const char *micro_err_format(int code)
{
  return (const char *)hexdsp(hx_micro_err_format, code);
}

//--------------------------------------------------------------------------
inline qstring hexrays_failure_t::desc(void) const
{
  qstring retval;
  hexdsp(hx_hexrays_failure_t_desc, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline void send_database(const hexrays_failure_t &err, bool silent)
{
  hexdsp(hx_send_database, &err, silent);
}

//--------------------------------------------------------------------------
inline ctype_t negated_relation(ctype_t op)
{
  return (ctype_t)(size_t)hexdsp(hx_negated_relation, op);
}

//--------------------------------------------------------------------------
inline type_sign_t get_op_signness(ctype_t op)
{
  return (type_sign_t)(size_t)hexdsp(hx_get_op_signness, op);
}

//--------------------------------------------------------------------------
inline ctype_t asgop(ctype_t cop)
{
  return (ctype_t)(size_t)hexdsp(hx_asgop, cop);
}

//--------------------------------------------------------------------------
inline ctype_t asgop_revert(ctype_t cop)
{
  return (ctype_t)(size_t)hexdsp(hx_asgop_revert, cop);
}

//--------------------------------------------------------------------------
inline size_t cnumber_t::print(char *buf, size_t bufsize, const tinfo_t &type, const citem_t *parent, bool *nice_stroff) const
{
  return (size_t)hexdsp(hx_cnumber_t_print, this, buf, bufsize, &type, parent, nice_stroff);
}

//--------------------------------------------------------------------------
inline uint64 cnumber_t::value(const tinfo_t &type) const
{
  uint64 retval;
  hexdsp(hx_cnumber_t_value, &retval, this, &type);
  return retval;
}

//--------------------------------------------------------------------------
inline void cnumber_t::assign(uint64 v, int nbytes, type_sign_t sign)
{
  hexdsp(hx_cnumber_t_assign, this, &v, nbytes, sign);
}

//--------------------------------------------------------------------------
inline int cnumber_t::compare(const cnumber_t &r) const
{
  return (int)(size_t)hexdsp(hx_cnumber_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int var_ref_t::compare(const var_ref_t &r) const
{
  return (int)(size_t)hexdsp(hx_var_ref_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ctree_visitor_t::apply_to(citem_t *item, citem_t *parent)
{
  return (int)(size_t)hexdsp(hx_ctree_visitor_t_apply_to, this, item, parent);
}

//--------------------------------------------------------------------------
inline int ctree_visitor_t::apply_to_exprs(citem_t *item, citem_t *parent)
{
  return (int)(size_t)hexdsp(hx_ctree_visitor_t_apply_to_exprs, this, item, parent);
}

//--------------------------------------------------------------------------
inline bool ctree_parentee_t::recalc_parent_types(void)
{
  return (uchar)(size_t)hexdsp(hx_ctree_parentee_t_recalc_parent_types, this) != 0;
}

//--------------------------------------------------------------------------
inline bool cfunc_parentee_t::calc_rvalue_type(tinfo_t *target, const cexpr_t *e)
{
  return (uchar)(size_t)hexdsp(hx_cfunc_parentee_t_calc_rvalue_type, this, target, e) != 0;
}

//--------------------------------------------------------------------------
inline int citem_locator_t::compare(const citem_locator_t &r) const
{
  return (int)(size_t)hexdsp(hx_citem_locator_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline bool citem_t::contains_label(void) const
{
  return (uchar)(size_t)hexdsp(hx_citem_t_contains_label, this) != 0;
}

//--------------------------------------------------------------------------
inline const citem_t *citem_t::find_parent_of(const citem_t *sitem) const
{
  return (const citem_t *)hexdsp(hx_citem_t_find_parent_of, this, sitem);
}

//--------------------------------------------------------------------------
inline cexpr_t &cexpr_t::assign(const cexpr_t &r)
{
  return *(cexpr_t *)hexdsp(hx_cexpr_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cexpr_t::compare(const cexpr_t &r) const
{
  return (int)(size_t)hexdsp(hx_cexpr_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void cexpr_t::replace_by(cexpr_t *r)
{
  hexdsp(hx_cexpr_t_replace_by, this, r);
}

//--------------------------------------------------------------------------
inline void cexpr_t::cleanup(void)
{
  hexdsp(hx_cexpr_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline void cexpr_t::put_number(cfunc_t *func, uint64 value, int nbytes, type_sign_t sign)
{
  hexdsp(hx_cexpr_t_put_number, this, func, &value, nbytes, sign);
}

//--------------------------------------------------------------------------
inline size_t cexpr_t::print1(char *buf, size_t bufsize, const cfunc_t *func) const
{
  return (size_t)hexdsp(hx_cexpr_t_print1, this, buf, bufsize, func);
}

//--------------------------------------------------------------------------
inline void cexpr_t::calc_type(bool recursive)
{
  hexdsp(hx_cexpr_t_calc_type, this, recursive);
}

//--------------------------------------------------------------------------
inline bool cexpr_t::equal_effect(const cexpr_t &r) const
{
  return (uchar)(size_t)hexdsp(hx_cexpr_t_equal_effect, this, &r) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::is_child_of(const citem_t *parent) const
{
  return (uchar)(size_t)hexdsp(hx_cexpr_t_is_child_of, this, parent) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::contains_operator(ctype_t needed_op, int times) const
{
  return (uchar)(size_t)hexdsp(hx_cexpr_t_contains_operator, this, needed_op, times) != 0;
}

//--------------------------------------------------------------------------
inline int cexpr_t::get_high_nbit_bound(int pbits, type_sign_t psign, bool *p_maybe_negative) const
{
  return (int)(size_t)hexdsp(hx_cexpr_t_get_high_nbit_bound, this, pbits, psign, p_maybe_negative);
}

//--------------------------------------------------------------------------
inline int cexpr_t::get_low_nbit_bound(type_sign_t psign, bool *p_maybe_negative) const
{
  return (int)(size_t)hexdsp(hx_cexpr_t_get_low_nbit_bound, this, psign, p_maybe_negative);
}

//--------------------------------------------------------------------------
inline bool cexpr_t::requires_lvalue(const cexpr_t *child) const
{
  return (uchar)(size_t)hexdsp(hx_cexpr_t_requires_lvalue, this, child) != 0;
}

//--------------------------------------------------------------------------
inline bool cexpr_t::has_side_effects(void) const
{
  return (uchar)(size_t)hexdsp(hx_cexpr_t_has_side_effects, this) != 0;
}

//--------------------------------------------------------------------------
inline cif_t &cif_t::assign(const cif_t &r)
{
  return *(cif_t *)hexdsp(hx_cif_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cif_t::compare(const cif_t &r) const
{
  return (int)(size_t)hexdsp(hx_cif_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline cloop_t &cloop_t::assign(const cloop_t &r)
{
  return *(cloop_t *)hexdsp(hx_cloop_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cfor_t::compare(const cfor_t &r) const
{
  return (int)(size_t)hexdsp(hx_cfor_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cwhile_t::compare(const cwhile_t &r) const
{
  return (int)(size_t)hexdsp(hx_cwhile_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cdo_t::compare(const cdo_t &r) const
{
  return (int)(size_t)hexdsp(hx_cdo_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int creturn_t::compare(const creturn_t &r) const
{
  return (int)(size_t)hexdsp(hx_creturn_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cgoto_t::compare(const cgoto_t &r) const
{
  return (int)(size_t)hexdsp(hx_cgoto_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int casm_t::compare(const casm_t &r) const
{
  return (int)(size_t)hexdsp(hx_casm_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline cinsn_t &cinsn_t::assign(const cinsn_t &r)
{
  return *(cinsn_t *)hexdsp(hx_cinsn_t_assign, this, &r);
}

//--------------------------------------------------------------------------
inline int cinsn_t::compare(const cinsn_t &r) const
{
  return (int)(size_t)hexdsp(hx_cinsn_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline void cinsn_t::replace_by(cinsn_t *r)
{
  hexdsp(hx_cinsn_t_replace_by, this, r);
}

//--------------------------------------------------------------------------
inline void cinsn_t::cleanup(void)
{
  hexdsp(hx_cinsn_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline cinsn_t &cinsn_t::new_insn(ea_t insn_ea)
{
  return *(cinsn_t *)hexdsp(hx_cinsn_t_new_insn, this, &insn_ea);
}

//--------------------------------------------------------------------------
inline cif_t &cinsn_t::create_if(cexpr_t *cnd)
{
  return *(cif_t *)hexdsp(hx_cinsn_t_create_if, this, cnd);
}

//--------------------------------------------------------------------------
inline void cinsn_t::print(int indent, vc_printer_t &vp, use_curly_t use_curly) const
{
  hexdsp(hx_cinsn_t_print, this, indent, &vp, use_curly);
}

//--------------------------------------------------------------------------
inline size_t cinsn_t::print1(char *buf, size_t bufsize, const cfunc_t *func) const
{
  return (size_t)hexdsp(hx_cinsn_t_print1, this, buf, bufsize, func);
}

//--------------------------------------------------------------------------
inline bool cinsn_t::is_ordinary_flow(void) const
{
  return (uchar)(size_t)hexdsp(hx_cinsn_t_is_ordinary_flow, this) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::contains_insn(ctype_t type, int times) const
{
  return (uchar)(size_t)hexdsp(hx_cinsn_t_contains_insn, this, type, times) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::collect_free_breaks(cinsnptrvec_t *breaks)
{
  return (uchar)(size_t)hexdsp(hx_cinsn_t_collect_free_breaks, this, breaks) != 0;
}

//--------------------------------------------------------------------------
inline bool cinsn_t::collect_free_continues(cinsnptrvec_t *continues)
{
  return (uchar)(size_t)hexdsp(hx_cinsn_t_collect_free_continues, this, continues) != 0;
}

//--------------------------------------------------------------------------
inline int cblock_t::compare(const cblock_t &r) const
{
  return (int)(size_t)hexdsp(hx_cblock_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int carglist_t::compare(const carglist_t &r) const
{
  return (int)(size_t)hexdsp(hx_carglist_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ccase_t::compare(const ccase_t &r) const
{
  return (int)(size_t)hexdsp(hx_ccase_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int ccases_t::compare(const ccases_t &r) const
{
  return (int)(size_t)hexdsp(hx_ccases_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline int cswitch_t::compare(const cswitch_t &r) const
{
  return (int)(size_t)hexdsp(hx_cswitch_t_compare, this, &r);
}

//--------------------------------------------------------------------------
inline member_t *ctree_item_t::get_memptr(struc_t **p_sptr) const
{
  return (member_t *)hexdsp(hx_ctree_item_t_get_memptr, this, p_sptr);
}

//--------------------------------------------------------------------------
inline lvar_t *ctree_item_t::get_lvar(void) const
{
  return (lvar_t *)hexdsp(hx_ctree_item_t_get_lvar, this);
}

//--------------------------------------------------------------------------
inline ea_t ctree_item_t::get_ea(void) const
{
  ea_t retval;
  hexdsp(hx_ctree_item_t_get_ea, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline int ctree_item_t::get_label_num(int gln_flags) const
{
  return (int)(size_t)hexdsp(hx_ctree_item_t_get_label_num, this, gln_flags);
}

//--------------------------------------------------------------------------
inline cexpr_t *lnot(cexpr_t *e)
{
  return (cexpr_t *)hexdsp(hx_lnot, e);
}

//--------------------------------------------------------------------------
inline cinsn_t *new_block(void)
{
  return (cinsn_t *)hexdsp(hx_new_block);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 0) cexpr_t *vcreate_helper(bool standalone, const tinfo_t &type, const char *format, va_list va)
{
  return (cexpr_t *)hexdsp(hx_vcreate_helper, standalone, &type, format, va);
}

//--------------------------------------------------------------------------
inline AS_PRINTF(3, 0) cexpr_t *vcall_helper(const tinfo_t &rettype, carglist_t *args, const char *format, va_list va)
{
  return (cexpr_t *)hexdsp(hx_vcall_helper, &rettype, args, format, va);
}

//--------------------------------------------------------------------------
inline cexpr_t *make_num(uint64 n, cfunc_t *func, ea_t ea, int opnum, type_sign_t sign, int size)
{
  return (cexpr_t *)hexdsp(hx_make_num, &n, func, &ea, opnum, sign, size);
}

//--------------------------------------------------------------------------
inline cexpr_t *make_ref(cexpr_t *e)
{
  return (cexpr_t *)hexdsp(hx_make_ref, e);
}

//--------------------------------------------------------------------------
inline cexpr_t *dereference(cexpr_t *e, int ptrsize, bool is_flt)
{
  return (cexpr_t *)hexdsp(hx_dereference, e, ptrsize, is_flt);
}

//--------------------------------------------------------------------------
inline void save_user_labels(ea_t func_ea, const user_labels_t *user_labels)
{
  hexdsp(hx_save_user_labels, &func_ea, user_labels);
}

//--------------------------------------------------------------------------
inline void save_user_cmts(ea_t func_ea, const user_cmts_t *user_cmts)
{
  hexdsp(hx_save_user_cmts, &func_ea, user_cmts);
}

//--------------------------------------------------------------------------
inline void save_user_numforms(ea_t func_ea, const user_numforms_t *numforms)
{
  hexdsp(hx_save_user_numforms, &func_ea, numforms);
}

//--------------------------------------------------------------------------
inline void save_user_iflags(ea_t func_ea, const user_iflags_t *iflags)
{
  hexdsp(hx_save_user_iflags, &func_ea, iflags);
}

//--------------------------------------------------------------------------
inline void save_user_unions(ea_t func_ea, const user_unions_t *unions)
{
  hexdsp(hx_save_user_unions, &func_ea, unions);
}

//--------------------------------------------------------------------------
inline user_labels_t *restore_user_labels(ea_t func_ea)
{
  return (user_labels_t *)hexdsp(hx_restore_user_labels, &func_ea);
}

//--------------------------------------------------------------------------
inline user_cmts_t *restore_user_cmts(ea_t func_ea)
{
  return (user_cmts_t *)hexdsp(hx_restore_user_cmts, &func_ea);
}

//--------------------------------------------------------------------------
inline user_numforms_t *restore_user_numforms(ea_t func_ea)
{
  return (user_numforms_t *)hexdsp(hx_restore_user_numforms, &func_ea);
}

//--------------------------------------------------------------------------
inline user_iflags_t *restore_user_iflags(ea_t func_ea)
{
  return (user_iflags_t *)hexdsp(hx_restore_user_iflags, &func_ea);
}

//--------------------------------------------------------------------------
inline user_unions_t *restore_user_unions(ea_t func_ea)
{
  return (user_unions_t *)hexdsp(hx_restore_user_unions, &func_ea);
}

//--------------------------------------------------------------------------
inline void cfunc_t::build_c_tree(void)
{
  hexdsp(hx_cfunc_t_build_c_tree, this);
}

//--------------------------------------------------------------------------
inline void cfunc_t::verify(allow_unused_labels_t aul, bool even_without_debugger) const
{
  hexdsp(hx_cfunc_t_verify, this, aul, even_without_debugger);
}

//--------------------------------------------------------------------------
inline size_t cfunc_t::print_dcl(char *buf, int bufsize) const
{
  return (size_t)hexdsp(hx_cfunc_t_print_dcl, this, buf, bufsize);
}

//--------------------------------------------------------------------------
inline size_t cfunc_t::print_dcl2(qstring *out) const
{
  return (size_t)hexdsp(hx_cfunc_t_print_dcl2, this, out);
}

//--------------------------------------------------------------------------
inline void cfunc_t::print_func(vc_printer_t &vp) const
{
  hexdsp(hx_cfunc_t_print_func, this, &vp);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_func_type(tinfo_t *type) const
{
  return (uchar)(size_t)hexdsp(hx_cfunc_t_get_func_type, this, type) != 0;
}

//--------------------------------------------------------------------------
inline lvars_t *cfunc_t::get_lvars(void)
{
  return (lvars_t *)hexdsp(hx_cfunc_t_get_lvars, this);
}

//--------------------------------------------------------------------------
inline sval_t cfunc_t::get_stkoff_delta(void)
{
  sval_t retval;
  hexdsp(hx_cfunc_t_get_stkoff_delta, &retval, this);
  return retval;
}

//--------------------------------------------------------------------------
inline citem_t *cfunc_t::find_label(int label)
{
  return (citem_t *)hexdsp(hx_cfunc_t_find_label, this, label);
}

//--------------------------------------------------------------------------
inline void cfunc_t::remove_unused_labels(void)
{
  hexdsp(hx_cfunc_t_remove_unused_labels, this);
}

//--------------------------------------------------------------------------
inline const char *cfunc_t::get_user_cmt(const treeloc_t &loc, cmt_retrieval_type_t rt) const
{
  return (const char *)hexdsp(hx_cfunc_t_get_user_cmt, this, &loc, rt);
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_cmt(const treeloc_t &loc, const char *cmt)
{
  hexdsp(hx_cfunc_t_set_user_cmt, this, &loc, cmt);
}

//--------------------------------------------------------------------------
inline int32 cfunc_t::get_user_iflags(const citem_locator_t &loc) const
{
  return (int32)(size_t)hexdsp(hx_cfunc_t_get_user_iflags, this, &loc);
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_iflags(const citem_locator_t &loc, int32 iflags)
{
  hexdsp(hx_cfunc_t_set_user_iflags, this, &loc, iflags);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::has_orphan_cmts(void) const
{
  return (uchar)(size_t)hexdsp(hx_cfunc_t_has_orphan_cmts, this) != 0;
}

//--------------------------------------------------------------------------
inline int cfunc_t::del_orphan_cmts(void)
{
  return (int)(size_t)hexdsp(hx_cfunc_t_del_orphan_cmts, this);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_user_union_selection(ea_t ea, intvec_t *path)
{
  return (uchar)(size_t)hexdsp(hx_cfunc_t_get_user_union_selection, this, &ea, path) != 0;
}

//--------------------------------------------------------------------------
inline void cfunc_t::set_user_union_selection(ea_t ea, const intvec_t &path)
{
  hexdsp(hx_cfunc_t_set_user_union_selection, this, &ea, &path);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::get_line_item(const char *line, int x, bool is_ctree_line, ctree_item_t *phead, ctree_item_t *pitem, ctree_item_t *ptail)
{
  return (uchar)(size_t)hexdsp(hx_cfunc_t_get_line_item, this, line, x, is_ctree_line, phead, pitem, ptail) != 0;
}

//--------------------------------------------------------------------------
inline hexwarns_t &cfunc_t::get_warnings(void)
{
  return *(hexwarns_t *)hexdsp(hx_cfunc_t_get_warnings, this);
}

//--------------------------------------------------------------------------
inline eamap_t &cfunc_t::get_eamap(void)
{
  return *(eamap_t *)hexdsp(hx_cfunc_t_get_eamap, this);
}

//--------------------------------------------------------------------------
inline boundaries_t &cfunc_t::get_boundaries(void)
{
  return *(boundaries_t *)hexdsp(hx_cfunc_t_get_boundaries, this);
}

//--------------------------------------------------------------------------
inline strvec_t &cfunc_t::get_pseudocode(void)
{
  return *(strvec_t *)hexdsp(hx_cfunc_t_get_pseudocode, this);
}

//--------------------------------------------------------------------------
inline bool cfunc_t::gather_derefs(const ctree_item_t &ci, udt_type_data_t *udm) const
{
  return (uchar)(size_t)hexdsp(hx_cfunc_t_gather_derefs, this, &ci, udm) != 0;
}

//--------------------------------------------------------------------------
inline void cfunc_t::cleanup(void)
{
  hexdsp(hx_cfunc_t_cleanup, this);
}

//--------------------------------------------------------------------------
inline cfuncptr_t decompile(func_t *pfn, hexrays_failure_t *hf)
{
  return cfuncptr_t((cfunc_t *)hexdsp(hx_decompile, pfn, hf));
}

//--------------------------------------------------------------------------
inline bool mark_cfunc_dirty(ea_t ea)
{
  return (uchar)(size_t)hexdsp(hx_mark_cfunc_dirty, &ea) != 0;
}

//--------------------------------------------------------------------------
inline void clear_cached_cfuncs(void)
{
  hexdsp(hx_clear_cached_cfuncs);
}

//--------------------------------------------------------------------------
inline bool has_cached_cfunc(ea_t ea)
{
  return (uchar)(size_t)hexdsp(hx_has_cached_cfunc, &ea) != 0;
}

//--------------------------------------------------------------------------
inline const char *get_ctype_name(ctype_t op)
{
  return (const char *)hexdsp(hx_get_ctype_name, op);
}

//--------------------------------------------------------------------------
inline qstring create_field_name(const tinfo_t &type, uval_t offset)
{
  qstring retval;
  hexdsp(hx_create_field_name, &retval, &type, &offset);
  return retval;
}

//--------------------------------------------------------------------------
inline bool install_hexrays_callback(hexrays_cb_t *callback, void *ud)
{
  return (uchar)(size_t)hexdsp(hx_install_hexrays_callback, callback, ud) != 0;
}

//--------------------------------------------------------------------------
inline int remove_hexrays_callback(hexrays_cb_t *callback, void *ud)
{
  return (int)(size_t)hexdsp(hx_remove_hexrays_callback, callback, ud);
}

//--------------------------------------------------------------------------
inline void __fastcall vdui_t::refresh_view(bool redo_mba)
{
  hexdsp(hx_vdui_t_refresh_view, this, redo_mba);
}

//--------------------------------------------------------------------------
inline void __fastcall vdui_t::refresh_ctext(bool activate)
{
  hexdsp(hx_vdui_t_refresh_ctext, this, activate);
}

//--------------------------------------------------------------------------
inline void vdui_t::switch_to(cfuncptr_t f, bool activate)
{
  hexdsp(hx_vdui_t_switch_to, this, &f, activate);
}

//--------------------------------------------------------------------------
inline cnumber_t *__fastcall vdui_t::get_number(void)
{
  return (cnumber_t *)hexdsp(hx_vdui_t_get_number, this);
}

//--------------------------------------------------------------------------
inline int __fastcall vdui_t::get_current_label(void)
{
  return (int)(size_t)hexdsp(hx_vdui_t_get_current_label, this);
}

//--------------------------------------------------------------------------
inline void __fastcall vdui_t::clear(void)
{
  hexdsp(hx_vdui_t_clear, this);
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::refresh_cpos(input_device_t idv)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_refresh_cpos, this, idv) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::get_current_item(input_device_t idv)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_get_current_item, this, idv) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::ui_rename_lvar(lvar_t *v)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_ui_rename_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::rename_lvar(lvar_t *v, const char *name, bool is_user_name)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_rename_lvar, this, v, name, is_user_name) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::ui_set_lvar_type(lvar_t *v)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_ui_set_lvar_type, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::set_lvar_type(lvar_t *v, const tinfo_t &type)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_set_lvar_type, this, v, &type) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::ui_edit_lvar_cmt(lvar_t *v)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_ui_edit_lvar_cmt, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::set_lvar_cmt(lvar_t *v, const char *cmt)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_set_lvar_cmt, this, v, cmt) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::ui_map_lvar(lvar_t *v)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_ui_map_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::ui_unmap_lvar(lvar_t *v)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_ui_unmap_lvar, this, v) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::map_lvar(lvar_t *from, lvar_t *to)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_map_lvar, this, from, to) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::set_strmem_type(struc_t *sptr, member_t *mptr)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_set_strmem_type, this, sptr, mptr) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::rename_strmem(struc_t *sptr, member_t *mptr)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_rename_strmem, this, sptr, mptr) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::set_global_type(ea_t ea)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_set_global_type, this, &ea) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::rename_global(ea_t ea)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_rename_global, this, &ea) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::rename_label(int label)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_rename_label, this, label) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::jump_enter(input_device_t idv, int omflags)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_jump_enter, this, idv, omflags) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::ctree_to_disasm(void)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_ctree_to_disasm, this) != 0;
}

//--------------------------------------------------------------------------
inline cmt_type_t __fastcall vdui_t::calc_cmt_type(size_t lnnum, cmt_type_t cmttype) const
{
  return (cmt_type_t)(size_t)hexdsp(hx_vdui_t_calc_cmt_type, this, lnnum, cmttype);
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::edit_cmt(const treeloc_t &loc)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_edit_cmt, this, &loc) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::edit_func_cmt(void)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_edit_func_cmt, this) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::del_orphan_cmts(void)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_del_orphan_cmts, this) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::set_num_radix(int base)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_set_num_radix, this, base) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::set_num_enum(void)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_set_num_enum, this) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::set_num_stroff(void)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_set_num_stroff, this) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::invert_sign(void)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_invert_sign, this) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::invert_bits(void)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_invert_bits, this) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::collapse_item(bool hide)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_collapse_item, this, hide) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::collapse_lvars(bool hide)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_collapse_lvars, this, hide) != 0;
}

//--------------------------------------------------------------------------
inline bool __fastcall vdui_t::split_item(bool split)
{
  return (uchar)(size_t)hexdsp(hx_vdui_t_split_item, this, split) != 0;
}

#ifdef __VC__
#pragma warning(pop)
#endif
#endif
