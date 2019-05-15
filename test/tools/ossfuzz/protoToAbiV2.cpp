#include <regex>
#include <numeric>
#include <boost/range/adaptor/reversed.hpp>
#include <test/tools/ossfuzz/protoToAbiV2.h>
#include <libsolidity/codegen/YulUtilFunctions.h>
#include <libdevcore/Whiskers.h>
#include <liblangutil/Exceptions.h>

using namespace std;
using namespace dev::solidity;
using namespace dev::test::abiv2fuzzer;

// Create a new variable declaration and append said variable to function parameter lists
// of callee functions.
// Variable named x_<i> where <i> is a monotonically increasing integer.
void ProtoConverter::createDeclAndParamList(
	std::string const& _type,
	dataType _dataType,
	std::string& _varName
)
{
	_varName = newVarName();

	// Declare array
	appendVarDeclToOutput(_type, _varName, getQualifier(_dataType));

	// Add typed params for calling public and external functions with said type
	appendTypedParams(
		calleeType::PUBLIC,
		isValueType(_dataType),
		_type,
		_varName,
		((m_varCounter == 1) ? delimiter::SKIP : delimiter::ADD)
	);
	appendTypedParams(
		calleeType::EXTERNAL,
		isValueType(_dataType),
		_type,
		_varName,
		((m_varCounter == 1) ? delimiter::SKIP : delimiter::ADD)
	);
}

void ProtoConverter::visitArrayType(std::string const& _baseType, ArrayType const& _x)
{
	std::string type = arrayTypeAsString(_baseType, _x);
	std::string varName;
	createDeclAndParamList(type, dataType::ARRAY, varName);
	// Resize-initialize array and add checks
	resizeInitArray(_x, _baseType, varName);
}

void ProtoConverter::visitType(
	dataType _dataType,
	std::string const& _type,
	std::string const& _value
)
{
	std::string varName;
	createDeclAndParamList(_type, _dataType, varName);
	addCheckedVarDef(_dataType, varName, _value);
}

void ProtoConverter::appendVarDeclToOutput(
	std::string const& _type,
	std::string const& _varName,
	std::string const& _qualifier
)
{
	m_output << Whiskers(R"(
	<type><?qual> <qualifier></qual> <varName>;)"
	)
		("type", _type)
		("qual", !_qualifier.empty())
		("qualifier", _qualifier)
		("varName", _varName)
		.render();
}

void ProtoConverter::bufferVarDef(std::string const& _varName, std::string const& _rhs)
{
	m_statebuffer << Whiskers(R"(
		<varName> = <rhs>;)"
	)
		("varName", _varName)
		("rhs", _rhs)
		.render();
}

void ProtoConverter::appendVarDefToOutput(std::string const& _varName, std::string const& _rhs)
{

	m_output << Whiskers(R"(
		<varName> = <rhs>;)"
	)
		("varName", _varName)
		("rhs", _rhs)
		.render();
}

void ProtoConverter::appendChecks(
	dataType _type,
	std::string const& _varName,
	std::string const& _rhs
)
{
	std::string check = {};
	switch (_type)
	{
	case dataType::STRING:
		check = Whiskers(R"(!stringCompare(<varName>, <value>))")
			("varName", _varName)
			("value", _rhs)
			.render();
		break;
	case dataType::BYTES:
		check = Whiskers(R"(!bytesCompare(<varName>, <value>))")
			("varName", _varName)
			("value", _rhs)
			.render();
		break;
	case dataType::VALUE:
		check = Whiskers(R"(<varName> != <value>)")
			("varName", _varName)
			("value", _rhs)
			.render();
		break;
	case dataType::ARRAY:
		solUnimplemented("Proto ABIv2 fuzzer: Invalid data type.");
	}

	// Each (failing) check returns a unique value to simplify debugging.
	m_checks << Whiskers(R"(
		if (<check>) return <returnVal>;)"
	)
		("check", check)
		("returnVal", std::to_string(m_returnValue++))
		.render();
}

void ProtoConverter::addVarDef(std::string const& _varName, std::string const& _rhs)
{
	// State variables cannot be assigned in contract-scope
	// Therefore, we buffer state variable assignments and
	// render them in function scope later.
	if (m_isStateVar)
		bufferVarDef(_varName, _rhs);
	else
		appendVarDefToOutput(_varName, _rhs);
}

void ProtoConverter::addCheckedVarDef(
	dataType _type,
	std::string const& _varName,
	std::string const& _rhs)
{
	addVarDef(_varName, _rhs);
	appendChecks(_type, _varName, _rhs);
}

// Runtime check for array length.
void ProtoConverter::checkResizeOp(std::string const& _varName,	unsigned _len)
{
	appendChecks(dataType::VALUE, _varName + ".length", std::to_string(_len));
}

/* Input(s)
 *   - Unsigned integer to be hashed
 *   - Width of desired uint value
 * Processing
 *   - Take hash of first parameter and mask it with the max unsigned value for given bit width
 * Output
 *   - string representation of uint value
 */
std::string ProtoConverter::uintValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width % 8 == 0),
		"Proto ABIv2 Fuzzer: Unsigned integer width is not a multiple of 8"
	);
	return maskUnsignedIntToHex(_counter, _width/4);
}

/* Input(s)
 *   - counter to be hashed to derive a value for Integer type
 *   - Width of desired int value
 * Processing
 *   - Take hash of first parameter and mask it with the max signed value for given bit width
 * Output
 *   - string representation of int value
 */
std::string ProtoConverter::intValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width % 8 == 0),
		"Proto ABIv2 Fuzzer: Signed integer width is not a multiple of 8"
	);
	return maskUnsignedIntToHex(_counter, ((_width/4) - 1));
}

std::string ProtoConverter::addressValueAsString(unsigned _counter)
{
	return Whiskers(R"(address(<value>))")
		("value", uintValueAsString(160, _counter))
		.render();
}

std::string ProtoConverter::fixedByteValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width >= 1 && _width <= 32),
		"Proto ABIv2 Fuzzer: Fixed byte width is not between 1--32"
	);
	// Masked value must contain twice the number of octet "f"'s as _width
	unsigned numMaskOctets = _width * 2;
	// Start position of substring equals totalHexStringLength - numMaskOctets
	// totalHexStringLength = 64 + 2 = 66
	// e.g., 0x12345678901234567890123456789012 is a total of 66 characters
	//      |---------------------^-----------|
	//      <--- start position---><--numMask->
	//      <-----------total length --------->
	// Note: This assumes that maskUnsignedIntToHex() invokes toHex(..., HexPrefix::Add)
	unsigned startPos = 66 - numMaskOctets;

	// Extracts the least significant numMaskOctets from the result of "maskUnsignedIntToHex",
	// and replaces "0x" with "hex\"...\"" string.
	// This is needed because solidity interprets a 20-byte 0x prefixed hex literal as an address
	// payable type.
	return Whiskers(R"(hex"<value>")")
		("value", maskUnsignedIntToHex(_counter, numMaskOctets).substr(startPos, numMaskOctets))
		.render();
}

std::string ProtoConverter::integerValueAsString(bool _sign, unsigned _width, unsigned _counter)
{
	if (_sign)
		return intValueAsString(_width, _counter);
	else
		return uintValueAsString(_width, _counter);
}

std::string ProtoConverter::bytesArrayTypeAsString(DynamicByteArrayType const& _x)
{
	switch (_x.type())
	{
	case DynamicByteArrayType::BYTES:
		return "bytes";
	case DynamicByteArrayType::STRING:
		return "string";
	}
}

std::string ProtoConverter::structTypeAsString(StructType const&)
{
	// TODO: Implement this
	return {};
}

void ProtoConverter::visit(IntegerType const& _x)
{
	visitType(
		dataType::VALUE,
		getIntTypeAsString(_x),
		integerValueAsString(isIntSigned(_x), getIntWidth(_x), getNextCounter())
	);
}

void ProtoConverter::visit(AddressType const& _x)
{
	visitType(
		dataType::VALUE,
		getAddressTypeAsString(_x),
		addressValueAsString(getNextCounter())
	);
}

void ProtoConverter::visit(FixedByteType const& _x)
{
	visitType(
		dataType::VALUE,
		getFixedByteTypeAsString(_x),
		fixedByteValueAsString(getFixedByteWidth(_x), getNextCounter())
	);
}

void ProtoConverter::visit(ValueType const& _x)
{
	switch (_x.value_type_oneof_case())
	{
		case ValueType::kInty:
			visit(_x.inty());
			break;
		case ValueType::kByty:
			visit(_x.byty());
			break;
		case ValueType::kAdty:
			visit(_x.adty());
			break;
		case ValueType::VALUE_TYPE_ONEOF_NOT_SET:
			break;
	}
}

void ProtoConverter::visit(DynamicByteArrayType const& _x)
{
	visitType(
		(_x.type() == DynamicByteArrayType::BYTES) ? dataType::BYTES : dataType::STRING,
		bytesArrayTypeAsString(_x),
		bytesArrayValueAsString()
	);
}

// TODO: Implement struct visitor
void ProtoConverter::visit(StructType const&)
{
}

std::string ProtoConverter::arrayDimInfoAsString(ArrayDimensionInfo const& _x)
{
	unsigned arrLength = getArrayLengthFromFuzz(_x.length());
	if (_x.is_static())
		return Whiskers(R"([<length>])")
		("length", std::to_string(arrLength))
		.render();
	else
		return Whiskers(R"([])").render();
}

void ProtoConverter::arrayDimensionsAsStringVector(
	ArrayType const& _x,
	std::vector<std::string>& _vecOfStr)
{
	solAssert(_x.info_size() > 0, "Proto ABIv2 Fuzzer: Array dimensions empty.");
	for (auto const& dim: _x.info())
		_vecOfStr.push_back(arrayDimInfoAsString(dim));
}

ProtoConverter::vecOfBoolUnsignedTy ProtoConverter::arrayDimensionsAsPairVector(
	ArrayType const& _x
)
{
	vecOfBoolUnsignedTy arrayDimsPairVector = {};
	for (auto const& dim: _x.info())
		arrayDimsPairVector.push_back(arrayDimInfoAsPair(dim));
	solAssert(!arrayDimsPairVector.empty(), "Proto ABIv2 Fuzzer: Array dimensions empty.");
	return arrayDimsPairVector;
}

std::string ProtoConverter::getValueByBaseType(ArrayType const& _x)
{
	switch (_x.base_type_oneof_case())
	{
	case ArrayType::kInty:
		return integerValueAsString(isIntSigned(_x.inty()), getIntWidth(_x.inty()), getNextCounter());
	case ArrayType::kByty:
		return fixedByteValueAsString(getFixedByteWidth(_x.byty()), getNextCounter());
	case ArrayType::kAdty:
		return addressValueAsString(getNextCounter());
	// TODO: Implement structs.
	case ArrayType::kStty:
	case ArrayType::BASE_TYPE_ONEOF_NOT_SET:
		solAssert(false, "Proto ABIv2 fuzzer: Invalid array base type");
	}
}

// Adds a resize operation for a given dimension of type `_type` and expression referenced
// by `_var`. `_isStatic` is true for statically sized dimensions, false otherwise.
// `_arrayLen` is equal to length of statically sized array dimension. For dynamically
// sized dimension, we use `getArrayLengthFromFuzz()` and a monotonically increasing
// counter to obtain actual length.
// Function returns dimension length.
unsigned ProtoConverter::resizeDimension(
	bool _isStatic,
	unsigned _arrayLen,
	std::string const& _var,
	std::string const& _type
)
{
	unsigned length;
	if (_isStatic)
		length = _arrayLen;
	else
	{
		length = getArrayLengthFromFuzz(_arrayLen, getNextCounter());

		// If local var, new T(l);
		// Else, l;
		std::string lhs, rhs;
		if (m_isStateVar)
		{
			lhs = _var + ".length";
			rhs = Whiskers(R"(<length>)")
				("length", std::to_string(length))
				.render();
		}
		else
		{
			lhs = _var;
			rhs = Whiskers(R"(new <type>(<length>))")
				("type", _type)
				("length", std::to_string(length))
				.render();
		}
		// If local var, x = new T(l);
		// Else, x.length = l;
		addVarDef(lhs, rhs);
	}

	// if (x.length != l)
	checkResizeOp(_var, length);
	return length;
}

void ProtoConverter::resizeHelper(
	ArrayType const& _x,
	std::vector<std::string> _arrStrVec,
	vecOfBoolUnsignedTy _arrInfoVec,
	std::string const& _var
)
{
	// Initialize value expressions if we have arrived at leaf node,
	// (depth-first) recurse otherwise.
	if (_arrInfoVec.empty())
	{
		// expression name is _var
		// value is a value of base type
		std::string value = getValueByBaseType(_x);
		// add assignment and check
		addCheckedVarDef(dataType::VALUE, _var, value);
	}
	else
	{
		auto& dim = _arrInfoVec.back();

		std::string type = std::accumulate(
			_arrStrVec.begin(),
			_arrStrVec.end(),
			std::string("")
		);
		unsigned length = resizeDimension(dim.first, dim.second, _var, type);
		// Recurse one level dimension down.
		_arrStrVec.pop_back();
		_arrInfoVec.pop_back();
		for (unsigned i = 0; i < length; i++)
			resizeHelper(_x, _arrStrVec, _arrInfoVec, _var + "[" + std::to_string(i) + "]");
	}
}

// This function takes care of properly resizing and initializing ArrayType.
// In parallel, it adds runtime checks on array bound and values.
void ProtoConverter::resizeInitArray(
	ArrayType const& _x,
	std::string const& _baseType,
	std::string const& _var
)
{
	vecOfBoolUnsignedTy arrInfoVec = arrayDimensionsAsPairVector(_x);
	std::vector<std::string> arrStrVec = {_baseType};
	arrayDimensionsAsStringVector(_x, arrStrVec);
	resizeHelper(_x, arrStrVec, arrInfoVec, _var);
}

// Returns array type from it's base type (e.g., int8) and array dimensions info contained in
// ArrayType.
std::string ProtoConverter::arrayTypeAsString(std::string const& _baseType, ArrayType const& _x)
{
	std::vector<std::string> typeStringVec = {_baseType};
	arrayDimensionsAsStringVector(_x, typeStringVec);

	return std::accumulate(
		typeStringVec.begin(),
		typeStringVec.end(),
		std::string("")
	);
}

void ProtoConverter::visit(ArrayType const& _x)
{
	// Bail out if input contains too few or too many dimensions.
	if (_x.info_size() == 0 || _x.info_size() > (int)s_maxArrayDimensions)
		return;

	string baseType = {};
	switch (_x.base_type_oneof_case())
	{
	case ArrayType::kInty:
		baseType = getIntTypeAsString(_x.inty());
		break;
	case ArrayType::kByty:
		baseType = getFixedByteTypeAsString(_x.byty());
		break;
	case ArrayType::kAdty:
		baseType = getAddressTypeAsString(_x.adty());
		break;
	case ArrayType::kStty:
	case ArrayType::BASE_TYPE_ONEOF_NOT_SET:
		return;
	}
	visitArrayType(baseType, _x);
}

void ProtoConverter::visit(NonValueType const& _x)
{
	switch (_x.nonvalue_type_oneof_case())
	{
	case NonValueType::kDynbytearray:
		visit(_x.dynbytearray());
		break;
	case NonValueType::kArrtype:
		visit(_x.arrtype());
		break;
	case NonValueType::kStype:
		visit(_x.stype());
		break;
	case NonValueType::NONVALUE_TYPE_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(Type const& _x)
{
	switch (_x.type_oneof_case())
	{
	case Type::kVtype:
		visit(_x.vtype());
		break;
	case Type::kNvtype:
		visit(_x.nvtype());
		break;
	case Type::TYPE_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(VarDecl const& _x)
{
	visit(_x.type());
}

std::string ProtoConverter::equalityChecksAsString()
{
	return m_checks.str();
}

std::string ProtoConverter::delimiterToString(delimiter _delimiter)
{
	switch (_delimiter)
	{
	case delimiter::ADD:
		return ", ";
	case delimiter::SKIP:
		return "";
	}
}

/* When a new variable is declared, we can invoke this function
 * to prepare the typed param list to be passed to callee functions.
 * We independently prepare this list for "public" and "external"
 * callee functions.
 */
void ProtoConverter::appendTypedParams(
	calleeType _calleeType,
	bool _isValueType,
	std::string const& _typeString,
	std::string const& _varName,
	delimiter _delimiter
)
{
	switch (_calleeType)
	{
	case calleeType::PUBLIC:
		appendTypedParamsPublic(_isValueType, _typeString, _varName, _delimiter);
		break;
	case calleeType::EXTERNAL:
		appendTypedParamsExternal(_isValueType, _typeString, _varName, _delimiter);
		break;
	}
}

// Adds the qualifier "calldata" to non-value parameter of an external function.
void ProtoConverter::appendTypedParamsExternal(
	bool _isValueType,
    std::string const& _typeString,
    std::string const& _varName,
    delimiter _delimiter
)
{
	std::string qualifiedTypeString = (
		_isValueType ?
		_typeString :
		_typeString + " calldata"
	);
	m_typedParamsExternal << Whiskers(R"(<delimiter><type> <varName>)")
		("delimiter", delimiterToString(_delimiter))
		("type", qualifiedTypeString)
		("varName", _varName)
		.render();
}

// Adds the qualifier "memory" to non-value parameter of an external function.
void ProtoConverter::appendTypedParamsPublic(
	bool _isValueType,
	std::string const& _typeString,
	std::string const& _varName,
	delimiter _delimiter
)
{
	std::string qualifiedTypeString = (
		_isValueType ?
		_typeString :
		_typeString + " memory"
		);
	m_typedParamsPublic << Whiskers(R"(<delimiter><type> <varName>)")
		("delimiter", delimiterToString(_delimiter))
		("type", qualifiedTypeString)
		("varName", _varName)
		.render();
}

std::string ProtoConverter::typedParametersAsString(calleeType _calleeType)
{
	switch (_calleeType)
	{
	case calleeType::PUBLIC:
		return m_typedParamsPublic.str();
	case calleeType::EXTERNAL:
		return m_typedParamsExternal.str();
	}
}

// Function that is called by the factory contract
void ProtoConverter::visit(TestFunction const& _x)
{
	m_output << Whiskers(R"(
	function f() public returns (uint) {
	)")
	.render();

	// Define state variables in function scope
	m_output << m_statebuffer.str();

	// TODO: Support more than one but less than N local variables
	visit(_x.local_vars());

	m_output << Whiskers(R"(
		uint returnVal = this.g_public(<parameter_names>);
		if (returnVal != 0)
			return returnVal;
		return (uint(1000) + this.g_external(<parameter_names>));
	}
	)")
	("parameter_names", YulUtilFunctions::suffixedVariableNameList("x_", 0, m_varCounter))
	.render();
}

void ProtoConverter::writeHelperFunctions()
{
	m_output << Whiskers(R"(
	function stringCompare(string memory a, string memory b) internal pure returns (bool) {
		if(bytes(a).length != bytes(b).length)
			return false;
		else
			return keccak256(bytes(a)) == keccak256(bytes(b));
	}
	)").render();

	m_output << Whiskers(R"(
	function bytesCompare(bytes memory a, bytes memory b) internal pure returns (bool) {
		if(a.length != b.length)
			return false;
		for (uint i = 0; i < a.length; i++)
			if (a[i] != b[i])
				return false;
		return true;
	}
	)").render();

	// These are callee functions that encode from storage, decode to
	// memory/calldata and check if decoded value matches storage value
	// return true on successful match, false otherwise
	m_output << Whiskers(R"(
	function g_public(<parameters_memory>) public view returns (uint) {
		<equality_checks>
		return 0;
	}

	function g_external(<parameters_calldata>) external view returns (uint) {
		<equality_checks>
		return 0;
	}
	)")
	("parameters_memory", typedParametersAsString(calleeType::PUBLIC))
	("equality_checks", equalityChecksAsString())
	("parameters_calldata", typedParametersAsString(calleeType::EXTERNAL))
	.render();
}

void ProtoConverter::visit(Contract const& _x)
{
	m_output << Whiskers(R"(pragma solidity >=0.0;
pragma experimental ABIEncoderV2;

contract Factory {
	function test() external returns (uint) {
		C c = new C();
		return c.f();
	}
}

contract C {
)").render();
	// TODO: Support more than one but less than N state variables
	visit(_x.state_vars());
	m_isStateVar = false;
	// Test function
	visit(_x.testfunction());
	writeHelperFunctions();
	m_output << "\n}";
}

string ProtoConverter::contractToString(Contract const& _input)
{
	visit(_input);
	return m_output.str();
}