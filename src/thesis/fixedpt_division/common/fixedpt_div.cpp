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

#include "fixedpt_div.h"

#include "algorithm/algorithm_description.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t number_of_simd,
                                                     encrypto::motion::MpcProtocol protocol,
                                                     bool check)
{
  // TODO tests
  std::uint32_t test1 = 1280;
  std::uint32_t test2 = 256;

  auto tmp1 = encrypto::motion::ToInput(1280);
  auto tmp2 = encrypto::motion::ToInput(256);
  std::vector<encrypto::motion::BitVector<>> tmp;
  tmp.insert(tmp.end(), tmp1.begin(), tmp1.end());
  tmp.insert(tmp.end(), tmp2.begin(), tmp2.end());

  encrypto::motion::ShareWrapper input{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw
          ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(tmp, 0)
          : party->In<encrypto::motion::MpcProtocol::kBmr>(tmp, 0)};
  const auto kPathToAlgorithm{std::string(encrypto::motion::kRootDir) +
                              "/circuits/fp/divison.bristol"};
  const auto divsion_algorithm{encrypto::motion::AlgorithmDescription::FromBristol(kPathToAlgorithm)};
  const auto result{input.Evaluate(division_algorithm)};
  encrypto::motion::ShareWrapper output;

  output = result.Out();
  std::cout << "output: " << output << std::endl;
  party->Run();
  party->Finish();
  if (check)
  {
    check_correctness(output);
  }
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
