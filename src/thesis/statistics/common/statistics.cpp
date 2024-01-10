// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "statistics.h"

#include <fstream>
#include <span>
#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/bmr/bmr_wire.h"
#include "secure_type/secure_unsigned_integer.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/block.h"
#include "utility/bit_vector.h"
#include "utility/config.h"
/*
Stores the input attributes of party_0 and party_1.
*/
struct Attributes
{
  std::vector<std::uint32_t> cleartext_input; // values for party_0 and categories for party_1.
  std::vector<encrypto::motion::SecureUnsignedInteger> shared_input;
} party_0, party_1;

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct StatisticsContext
{
  Attributes party_0, party_1;
};

/*
 * Runs the protocol and returns the runtime statistics.
 * First reads in the files and then calculates sum, mean, min and max
 */
encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer &party, const std::string &input_file_path, encrypto::motion::MpcProtocol protocol)
{
  std::vector<std::uint32_t> id;
  // Get respective party id
  auto party_id = party->GetConfiguration()->GetMyId();
  // Load the correct input from file via file_path from command line
  const auto [party_0_temp, party_1_temp, id_temp] =
      GetFileInput(party_id, input_file_path);
  party_0.cleartext_input = party_0_temp;
  party_1.cleartext_input = party_1_temp;
  id = id_temp;
  // insert the Input for party 0 and party 1
  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i++)
  {
    party_0.shared_input.push_back(
        party->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input[i], 0));
  }
  for (std::size_t i = 0; i < party_1.cleartext_input.size(); i++)
  {
    party_1.shared_input.push_back(party->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(party_1.cleartext_input[i], 1));
  }
  // Create the context for the circuit
  StatisticsContext context{party_0, party_1};
  // Create the circuit
  encrypto::motion::SecureUnsignedInteger sum = CreateSumCircuit(context);
  // Create the output gate
  sum = sum.Out();

  party->Run();
  std::cout << "Sum " << sum.As<std::uint32_t>() << std::endl;
  party->Finish();

  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}

/**
 * Takes inputs from file in path.
 */
std::tuple<std::vector<std::uint32_t>, std::vector<std::uint32_t>, std::vector<std::uint32_t>>
GetFileInput(std::size_t party_id, const std::string &path)
{
  std::ifstream infile;
  std::vector<std::uint32_t> party_0, party_1, id;
  std::uint32_t n;

  infile.open(path);
  if (!infile.is_open())
    throw std::runtime_error("Could not open Statistics File");
  std::uint32_t i = 0;
  while (infile >> n)
  {
    if (party_id == 0)
    {
      party_0.push_back(n); // Assigns input values to party_0.
      party_1.push_back(n); // Assigns dummy input to party_1.
    }
    else
    {
      party_0.push_back(n); // Assigns dummy input to party_0..
      party_1.push_back(n); // Assigns input values to party_1.
    }
    id.push_back(i);
    i++;
  }
  infile.close();
  return {party_0, party_1, id};
}

/**
 * Calculate the Mean of the values given by the two parties
 * */
int CreateMeanCircuit(
    StatisticsContext context)
{
  auto party_0_values = context.party_0.shared_input, party_1_categories = context.party_1.shared_input;
  encrypto::motion::SecureUnsignedInteger sum = CreateSumCircuit(context);
  int open_sum = sum.Out().As<std::uint32_t>();
  int mean = open_sum / (party_0_values.size() + party_1_categories.size());
  return mean;
}

encrypto::motion::SecureUnsignedInteger CreateSumCircuit(
    StatisticsContext context)
{
  auto party_0_values = context.party_0.shared_input, party_1_values = context.party_1.shared_input;
  encrypto::motion::SecureUnsignedInteger sum;
  for (std::size_t i = 0; i < party_0_values.size(); i++)
  {
    sum += party_0_values[i].Get();
  }
  for (std::size_t i = 0; i < party_1_values.size(); i++)
  {
    sum += party_1_values[i].Get();
  }
  return sum;
}

/*SecureUnsignedInteger CreateMaxCircuit(
    StatisticsContext context)
{
  ""
  "Secure maximum of all given elements in x, similar to Python's built-in max()."
  "" auto party_0_values = context.party_0.shared_input,
          party_1_values = context.party_1.shared_input;
  encrypto::motion::SecureUnsignedInteger max = 0;
  party_0_values.insert(party_0_values.end(), party_1_values.begin(), party_1_values.end());
  if(party_0_values.empty()) {
        throw std::invalid_argument("Vector is empty");
    }
  encrypto::motion::SecureUnsignedInteger max_value = party_0_values[0];
  for (std::size_t i = 0; i < party_0_values.size(); i++)
  {

    Here we need to change the Comparison and replacement function
    if (party_0_values[i] > max_value)
    {
      max_value = party_0_values[i];
    }
  }


  return max_value;
}

SecureUnsignedInteger CreateMinCircuit(
    StatisticsContext context)
{
  ""
  "Secure maximum of all given elements in x, similar to Python's built-in max()."
  "" auto party_0_values = context.party_0.shared_input,
          party_1_values = context.party_1.shared_input;
  party_0_values.insert(party_0_values.end(), party_1_values.begin(), party_1_values.end());
  if(party_0_values.empty()) {
        throw std::invalid_argument("Vector is empty");
    }
  encrypto::motion::SecureUnsignedInteger max_value = party_0_values[0];
  for (std::size_t i = 0; i < party_0_values.size(); i++)
  {

    Here we need to change the Comparison and replacement function
    if (party_0_values[i] > max_value)
    {
      max_value = party_0_values[i];
    }
  }


  return max_value;
}
*/