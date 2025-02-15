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
#include "base/backend.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "secure_type/secure_unsigned_integer.h"
#include "utility/block.h"
#include "utility/config.h"

template <typename T>
encrypto::motion::ShareWrapper DummyArithmeticGmwShare(encrypto::motion::PartyPointer &party,
                                                       std::size_t bit_size,
                                                       std::size_t number_of_simd)
{
  std::vector<encrypto::motion::WirePointer> wires(1);
  const std::vector<T> dummy_input(number_of_simd, 0);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  wires[0] = register_pointer->EmplaceWire<encrypto::motion::proto::arithmetic_gmw::Wire<T>>(
      dummy_input, *backend);
  wires[0]->SetOnlineFinished();

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::arithmetic_gmw::Share<T>>(wires));
}

encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer &party, std::size_t number_of_simd, std::size_t bit_size,
    encrypto::motion::MpcProtocol protocol)
{

  const std::vector<encrypto::motion::BitVector<>> temporary_bool(
      bit_size, encrypto::motion::BitVector<>(number_of_simd));
  encrypto::motion::SecureUnsignedInteger a, b;
  encrypto::motion::ShareWrapper a_s, b_s;
  switch (protocol)
  {
  case encrypto::motion::MpcProtocol::kBooleanGmw:  
    a = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(temporary_bool, 0);
    b = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(temporary_bool, 0);
    a * b;
    break;
  case encrypto::motion::MpcProtocol::kArithmeticGmw:
    a_s = DummyArithmeticGmwShare<std::uint32_t>(party, bit_size, number_of_simd);
    b_s = DummyArithmeticGmwShare<std::uint32_t>(party, bit_size, number_of_simd);
    a_s * b_s;
    break;
  case encrypto::motion::MpcProtocol::kBmr:
    a = party->In<encrypto::motion::MpcProtocol::kBmr>(temporary_bool, 0);
    b = party->In<encrypto::motion::MpcProtocol::kBmr>(temporary_bool, 0);
    a = a * b;
    break;
  default:
    break;
  }
  party->Run();
  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
