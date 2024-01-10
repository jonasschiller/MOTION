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
  std::vector<encrypto::motion::SecureUnsignedInteger> id;
} party_0, party_1;

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct StatisticsContext
{
  Attributes party_0, party_1;
  Results results;
};

struct Results
{
  encrypto::motion::SecureUnsignedInteger mean;
  encrypto::motion::SecureUnsignedInteger max;
  encrypto::motion::SecureUnsignedInteger min;
  encrypto::motion::SecureUnsignedInteger sum;
} results;

encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer &party, const std::string &input_file_path, encrypto::motion::MpcProtocol protocol)
{
  std::vector<std::uint32_t> id;
  std::uint32_t zero = 0;

  auto party_id = party->GetConfiguration()->GetMyId();

  const auto [party_0_temp, party_1_temp, id_temp] =
      GetFileInput(party_id, input_file_path);
  party_0.cleartext_input = party_0_temp;
  party_1.cleartext_input = party_1_temp;
  id = id_temp;

  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i++)
  {
    party_0.shared_input.push_back(
        party->In<encrypto::motion::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input[i], 0));
    party_1.shared_input.push_back(party->In < encrypto::motion::MpcProtocol::kArithemticGmw(party_1.cleartext_input[i], 1));
    party_0.id.push_back(
        party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(encrypto::motion::ToInput(id[i]), 0));
    party_1.id.push_back(
        party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(encrypto::motion::ToInput(id[i]), 1));
  }
  StatisticsContext context{party_0, party_1, results};
  results.mean = CreateMeanCircuit(context);
  // Constructs an output gate for each bin.
  results.mean = results.mean.Out();
  results.sum = results.sum.Out();

  party->Run();
  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}

/**
 * Takes inputs from file in path.
 */
std::tuple<std::vector<std::uint32_t>, std::vector<std::uint32_t>, std::vector<std::uint32_t>>
GetFileInput(std::size_t party_id, const std::string &path, std::uint32_t number_of_bins)
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
encrypto::motion::SecureUnsignedInteger CreateMeanCircuit(
    StatisticsContext context)
{
  auto party_0_values = context.party_0.shared_input, party_1_categories = context.party_1.shared_input;
  encrypto::motion::SecureUnsignedInteger sum = CreateSumCircuit(context);
  encrypto::motion::SecureUnsignedInteger mean = sum / (party_0_values.size() + party_1_categories.size());
  return mean;
}

encrypto::motion::SecureUnsignedInteger CreateSumCircuit(
    StatisticsContext context)
{
  auto party_0_values = context.party_0.shared_input, party_1_values = context.party_1.shared_input;
  encrypto::motion::SecureUnsignedInteger sum1 = 0;
  encrypto::motion::SecureUnsignedInteger sum2 = 0;
  for (std::size_t i = 0; i < party_0.size(); i++)
  {
    sum1 += party_0_values[i];
  }
  for (std::size_t i = 0; i < party_0.size(); i++)
  {
    sum2 += party_1_values[i];
  }
  return sum1 + sum2;
}

// SecureUnsignedInteger CreateMaxCircuit(
//     StatisticsContext context)
// {
//   ""
//   "Secure maximum of all given elements in x, similar to Python's built-in max()."
//   "" auto party_0_values = context.party_0.shared_input,
//           party_1_values = context.party_1.shared_input;
//   SecureUnsignedInteger max1 = 0;
//   SecureUnsignedInteger max2 = 0;
//   if len (x) == 1:
//             x = x[0]
//         if iter(x) is x:
//             x = list(x)
//         n = len(x)
//         if not n:
//             raise ValueError('max() arg is an empty sequence')

//         if n == 1:
//             return x[0]

//         if key is None:
//             key = lambda a: a
//         max0 = self.max(x[:n//2], key=key)
//         max1 = self.max(x[n//2:], key=key)
//         return self.if_else(key(max0) < key(max1), max1, max0)
//   return sum1 + sum2;
// }
