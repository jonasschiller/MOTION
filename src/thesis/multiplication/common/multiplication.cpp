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

#include "multiplication.h"

#include "algorithm/algorithm_description.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"


encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer& party, std::size_t number_of_simd, std::size_t bit_size,
    encrypto::motion::MpcProtocol protocol) {
  std::vector<uint32_t> temporary(1000000);
  encrypto::motion::SecureUnsignedInteger a,b;
  a = party -> In<encrypto::motion::MpcProtocol::kArithmeticGmw>(temporary,1);
  b = party -> In<encrypto::motion::MpcProtocol::kArithmeticGmw>(temporary,1);
  a=a*b;
  auto output = a.Out();

  party->Run();
  party->Finish();
  auto result=output.As<std::vector<uint32_t>>();
  std::cout << result[i] << std::endl;
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}