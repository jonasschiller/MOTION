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

#include "psi.h"

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
  std::vector<encrypto::motion::SecureUnsignedInteger> ids;
} party_0, party_1;

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct PsiContext
{
  Attributes party_0, party_1;
  encrypto::motion::ShareWrapper full_zero;
  std::vector<encrypto::motion::SecureUnsignedInteger> results;
};

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

  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i++)
  {
    party_0.id.push_back(
        party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(encrypto::motion::ToInput(party_0.cleartext_input[i]), 0));
    party_1.id.push_back(
        party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(encrypto::motion::ToInput(party_1.cleartext_input[i]), 1));
  }

  encrypto::motion::ShareWrapper full_zero = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(
      encrypto::motion::BitVector<>(1, false), 0);
  std::vector<encrypto::motion::SecureUnsignedInteger> result;
  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i++)
  {
    result.push_back(0);
  }
  PsiContext context{party_0, party_1, result, full_zero};
  std::vector<encrypto::motion::SecureUnsignedInteger> output = CreatePsiCircuit(context);
  // Constructs an output gate for each bin.
  for (std::size_t i = 0; i < output.size(); i++)
    output[i] = output[i].Out();
  party->Run();
  // Converts the outputs to integers.
  std::vector<std::uint32_t> result;
  for (auto each_output : output)
    result.push_back(each_output.As<std::uint32_t>());

  if (print_output)
  {
    for (std::size_t i = 0; i < number_of_bins; i++)
    {
      std::cout << " " << i << "," << result[i] << std::endl;
    }
  }
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
  std::vector<std::uint32_t> party_0, party_1;
  std::uint32_t n;

  infile.open(path);
  if (!infile.is_open())
    throw std::runtime_error("Could not open Index file");
  while (infile >> n)
  {
    if (party_id == 0)
    {
      party_0.push_back(n); // Assigns input values to party_0.
      party_1.push_back(0); // Assigns dummy input to party_1.
    }
    else
    {
      party_0.push_back(0); // Assigns dummy input to party_0..
      party_1.push_back(n); // Assigns input values to party_1.
    }
  }
  infile.close();
  return {party_0, party_1};
}

/**
 * Constructs the cross tabs of the given data in CrossTabsContext.
 * */
std::vector<encrypto::motion::SecureUnsignedInteger> CreatePsiCircuit(
    PsiContext context)
{
  auto party_0_id = context.party_0.id, ,
       party_1_id = context.party_1.id,
       encrypto::motion::ShareWrapper id_match;

  for (std::size_t i = 0; i < party_0.size(); i++)
  {
    for (std::size_t j = 0; j < party_1_id.size(); j++)
    {
      id_match = (party_0_id[i] == party_1_id[j]); // Checks if the indices are the same.
      // Concatenates keep so that it has the same length as party_0_values[i].
      std::vector<encrypto::motion::ShareWrapper> keep_concat;
      keep_concat.push_back(keep);
      for (std::size_t i = 0; i < 31; i++)
        keep_concat.push_back(context.full_zero);
      keep = encrypto::motion::ShareWrapper::Concatenate(keep_concat);

      // Assigns party_0_values[i] in keep only if keep is 'true'.
      keep = keep.Convert<encrypto::motion::MpcProtocol::kArithmeticGmw>();
      keep = keep * party_0_id[i].Get();

      // Adds keep to the result.
      context.results.push_back(encrypto::motion::SecureUnsignedInteger(keep));
    }
  }
  return context.results;
}