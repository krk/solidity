#pragma once

#include <ostream>
#include <sstream>
#include <test/tools/ossfuzz/abiV2Proto.pb.h>
#include <libdevcore/Whiskers.h>
#include <libdevcore/Keccak256.h>
#include <libdevcore/FixedHash.h>
#include <boost/algorithm/string.hpp>

namespace dev
{
namespace test
{
namespace abiv2fuzzer
{
class ProtoConverter
{
public:
	ProtoConverter()
	{
		m_isStateVar = true;
		m_counter = 0;
		m_varCounter = 0;
		// Return value on first error condition is 1,
		// incremented for subsequent error conditions.
		m_returnValue = 1;
	}
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;
	std::string contractToString(Contract const& _input);

private:
	typedef std::vector<std::pair<bool,unsigned>> vecOfBoolUnsignedTy;

	enum class delimiter
	{
		ADD,
		SKIP
	};
	enum class calleeType
	{
		PUBLIC,
		EXTERNAL
	};
	enum class dataType
	{
		BYTES,
		STRING,
		VALUE,
		ARRAY
	};

	void visit(IntegerType const&);
	void visit(FixedByteType const&);
	void visit(AddressType const&);
	void visit(ArrayType const&);
	void visit(DynamicByteArrayType const&);
	void visit(StructType const&);
	void visit(ValueType const&);
	void visit(NonValueType const&);
	void visit(Type const&);
	void visit(VarDecl const&);
	void visit(TestFunction const&);
	void visit(Contract const&);
	std::string getValueByBaseType(ArrayType const&);
	void resizeInitArray(
		ArrayType const& _x,
		std::string const& _baseType,
		std::string const& _var
	);
	unsigned resizeDimension(
		bool _isStatic,
		unsigned _arrayLen,
		std::string const& _var,
		std::string const& _type
	);
	void resizeHelper(
		ArrayType const& _x,
		std::vector<std::string> _arrStrVec,
		vecOfBoolUnsignedTy _arrInfoVec,
		std::string const& _var
	);

	// Utility
	void appendChecks(dataType _type, std::string const& _varName, std::string const& _rhs);
	void addVarDef(std::string const& _varName, std::string const& _rhs);
	void addCheckedVarDef(dataType _type, std::string const& _varName, std::string const& _rhs);
	void appendTypedParams(
			calleeType _calleeType,
			bool _isValueType,
			std::string const& _typeString,
			std::string const& _varName,
			delimiter _delimiter
	);
	void appendTypedParamsPublic(
			bool _isValueType,
			std::string const& _typeString,
			std::string const& _varName,
			delimiter _delimiter = delimiter::ADD
	);
	void appendTypedParamsExternal(
			bool _isValueType,
			std::string const& _typeString,
			std::string const& _varName,
			delimiter _delimiter = delimiter::ADD
	);
	void appendVarDeclToOutput(
		std::string const& _type,
		std::string const& _varName,
		std::string const& _qualifier
	);
	void checkResizeOp(std::string const& _varName, unsigned _len);
	void visitType(dataType _dataType, std::string const& _type, std::string const& _value);
	void visitArrayType(std::string const&, ArrayType const&);
	void createDeclAndParamList(
		std::string const& _type,
		dataType _dataType,
		std::string& _varName
	);
	void appendVarDefToOutput(std::string const& _varName, std::string const& _rhs);
	std::string equalityChecksAsString();
	std::string typedParametersAsString(calleeType _calleeType);
	void writeHelperFunctions();
	void bufferVarDef(std::string const& _varName, std::string const& _rhs);

	// Inline functions
	inline unsigned getNextCounter()
	{
		return m_counter++;
	}

	inline std::string newVarName()
	{
		return  ("x_" + std::to_string(m_varCounter++));
	}

	// String and bytes literals are derived by hashing a monotonically increasing
	// counter and enclosing the said hash inside double quotes.
	inline std::string bytesArrayValueAsString()
	{
		return ("\"" + toHex(hashUnsignedInt(getNextCounter()), HexPrefix::DontAdd) + "\"");
	}

	inline std::string getQualifier(dataType _dataType)
	{
		return (!(isValueType(_dataType) || m_isStateVar) ? "memory" : "");
	}

	// Static declarations
	static std::string structTypeAsString(StructType const& _x);
	static std::string intValueAsString(unsigned _width, unsigned _counter);
	static std::string uintValueAsString(unsigned _width, unsigned _counter);
	static std::string integerValueAsString(bool _sign, unsigned _width, unsigned _counter);
	static std::string addressValueAsString(unsigned _counter);
	static std::string fixedByteValueAsString(unsigned _width, unsigned _counter);
	static std::vector<std::pair<bool, unsigned>> arrayDimensionsAsPairVector(ArrayType const& _x);
	static std::string arrayDimInfoAsString(ArrayDimensionInfo const& _x);
	static void arrayDimensionsAsStringVector(
		ArrayType const& _x,
		std::vector<std::string>&
	);
	static std::string bytesArrayTypeAsString(DynamicByteArrayType const& _x);
	static std::string arrayTypeAsString(std::string const&, ArrayType const&);
	static std::string delimiterToString(delimiter _delimiter);

	// Static inline functions
	static inline bool isValueType(dataType _dataType)
	{
		return (_dataType == dataType::VALUE);
	}

	static inline unsigned getIntWidth(IntegerType const& _x)
	{
		return (8 * ((_x.width() % 32) + 1));
	}

	static inline bool isIntSigned(IntegerType const& _x)
	{
		return _x.is_signed();
	}

	static inline std::string getIntTypeAsString(IntegerType const& _x)
	{
		return ((isIntSigned(_x) ? "int" : "uint") + std::to_string(getIntWidth(_x)));
	}

	static inline unsigned getFixedByteWidth(FixedByteType const& _x)
	{
		return ((_x.width() % 32) + 1);
	}

	static inline std::string getFixedByteTypeAsString(FixedByteType const& _x)
	{
		return ("bytes" + std::to_string(getFixedByteWidth(_x)));
	}

	static inline std::string getAddressTypeAsString(AddressType const& _x)
	{
		return (_x.payable() ? "address payable": "address");
	}

	// Convert _counter to string and return its keccak256 hash.
	static inline u256 hashUnsignedInt(unsigned _counter)
	{
		return keccak256(
			boost::algorithm::to_lower_copy(
				std::to_string(_counter),
				std::locale::classic()
			)
		);
	}

	static inline u256 maskUnsignedInt(unsigned _counter, unsigned _numMaskOctets)
	{
	  return hashUnsignedInt(_counter) & u256("0x" + std::string(_numMaskOctets, 'f'));
	}

	// Requires caller to pass number of octets (twice the number of bytes) as second argument.
	// Note: Don't change HexPrefix::Add. See comment in fixedByteValueAsString().
	static inline std::string maskUnsignedIntToHex(unsigned _counter, unsigned _numMaskOctets)
	{
		return toHex(maskUnsignedInt(_counter, _numMaskOctets), HexPrefix::Add);
	}

	static inline unsigned getArrayLengthFromFuzz(unsigned _fuzz, unsigned _counter = 0)
	{
		return (((_fuzz + _counter) % s_maxArrayLength) + 2);
	}

	static inline std::pair<bool, unsigned> arrayDimInfoAsPair(ArrayDimensionInfo const& _x)
	{
		return std::make_pair(_x.is_static(), getArrayLengthFromFuzz(_x.length()));
	}

	// Contains the test program
	std::ostringstream m_output;
	// Temporary storage for state variable definitions
	std::ostringstream m_statebuffer;
	// Contains a subset of the test program. This subset contains
	// checks to be encoded in the test program
	std::ostringstream m_checks;
	// Contains a subset of the test program. This subset contains
	// typed parameter list to be passed to callee functions.
	std::ostringstream m_typedParamsExternal;
	std::ostringstream m_typedParamsPublic;
	// Return value in case of error.
	unsigned m_returnValue;
	// Predicate that is true if we are in contract scope
	bool m_isStateVar;
	unsigned m_counter;
	unsigned m_varCounter;
	static unsigned constexpr s_maxArrayLength = 3;
	static unsigned constexpr s_maxArrayDimensions = 4;
};
}
}
}