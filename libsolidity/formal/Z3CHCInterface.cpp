/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <libsolidity/formal/Z3CHCInterface.h>

#include <liblangutil/Exceptions.h>
#include <libdevcore/CommonIO.h>

using namespace std;
using namespace dev;
using namespace dev::solidity::smt;

Z3CHCInterface::Z3CHCInterface():
	m_context(make_shared<z3::context>()),
	m_solver(*m_context),
	m_z3Interface(make_shared<Z3Interface>(m_context)),
	m_variables(*m_context)
{
	// This needs to be set globally.
	z3::set_param("rewriter.pull_cheap_ite", true);
	// This needs to be set in the context.
	m_context->set("timeout", queryTimeout);
}

void Z3CHCInterface::declareVariable(string const& _name, Sort const& _sort)
{
	if (m_z3Interface->constants().count(_name))
		return;
	m_z3Interface->declareVariable(_name, _sort);
	if (_sort.kind != Kind::Function)
		m_variables.push_back(m_z3Interface->constants().at(_name));
}

void Z3CHCInterface::registerRelation(Expression const& _expr)
{
	m_solver.register_relation(m_z3Interface->functions().at(_expr.name));
}

void Z3CHCInterface::addRule(Expression const& _expr, string const& _name)
{
	z3::expr rule = m_z3Interface->toZ3Expr(_expr);
	if (m_variables.empty())
		m_solver.add_rule(rule, m_context->str_symbol(_name.c_str()));
	else
	{
		z3::expr_vector variables(*m_context);
		for (auto const& var: m_z3Interface->constants())
			variables.push_back(var.second);
		z3::expr boundRule = z3::forall(variables, rule);
		cout << "\n\nBound rule:\n" << boundRule << endl;
		m_solver.add_rule(boundRule, m_context->str_symbol(_name.c_str()));
	}
}

pair<CheckResult, vector<string>> Z3CHCInterface::query(Expression const& _expr)
{
	CheckResult result;
	vector<string> values;
	cout << m_solver << endl;
	try
	{
		z3::expr z3Expr = m_z3Interface->toZ3Expr(_expr);
		switch (m_solver.query(z3Expr))
		{
		case z3::check_result::sat:
		{
			result = CheckResult::SATISFIABLE;
			cout << m_solver.get_answer() << endl;
			// TODO retrieve model.
			break;
		}
		case z3::check_result::unsat:
		{
			result = CheckResult::UNSATISFIABLE;
			cout << m_solver.get_answer() << endl;
			// TODO retrieve invariants.
			break;
		}
		case z3::check_result::unknown:
			result = CheckResult::UNKNOWN;
			break;
		}
		// TODO retrieve model / invariants
	}
	catch (z3::exception const& _e)
	{
		result = CheckResult::ERROR;
		values.clear();
	}

	return make_pair(result, values);
}
