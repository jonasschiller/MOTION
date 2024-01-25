// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include "comparison.h"

#include <fstream>
#include <span>
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer &party, encrypto::motion::MpcProtocol protocol,
    std::size_t number_of_simd, std::size_t bit_size)
{
  std::uint32_t input = 0;
  std::vector<encrypto::motion::SecureUnsignedInteger> a(number_of_simd), b(number_of_simd);
  std::vector<encrypto::motion::ShareWrapper> output(number_of_simd);
  switch (protocol)
  {
  case encrypto::motion::MpcProtocol::kBooleanGmw:
  {
    for (std::size_t i = 0; i < number_of_simd; i++)
    {
      a[i] = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(encrypto::motion::ToInput(input), 0);
      b[i] = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(encrypto::motion::ToInput(input), 0);
    }
    break;
  }
  case encrypto::motion::MpcProtocol::kBmr:
  {
    for (std::size_t i = 0; i < number_of_simd; i++)
    {
      a[i] = party->In<encrypto::motion::MpcProtocol::kBmr>(encrypto::motion::ToInput(input), 0);
      b[i] = party->In<encrypto::motion::MpcProtocol::kBmr>(encrypto::motion::ToInput(input), 0);
    }

    break;
  }
  default:
    throw std::invalid_argument("Invalid MPC protocol");
  }

  for (std::size_t i = 0; i < number_of_simd, i++)
  {
    output[i] = a[i] > b[i];
  }

  output[number_of_simd - 1] = output[number_of_simd - 1].Out();

  party->Run();

  party->Finish();

  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();

  return statistics.front();
}
