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

template <typename T>
encrypto::motion::ShareWrapper DummyArithmeticGmwShare(encrypto::motion::PartyPointer& party,
                                                       std::size_t bit_size,
                                                       std::size_t number_of_simd) {
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


encrypto::motion::ShareWrapper DummyBmrShare(encrypto::motion::PartyPointer& party,
                                             std::size_t number_of_wires,
                                             std::size_t number_of_simd) {
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto& w : wires) {
    auto bmr_wire{
        register_pointer->EmplaceWire<encrypto::motion::proto::bmr::Wire>(dummy_input, *backend)};
    w = bmr_wire;
    bmr_wire->GetMutablePublicKeys() = encrypto::motion::Block128Vector::MakeZero(
        backend->GetConfiguration()->GetNumOfParties() * number_of_simd);
    bmr_wire->GetMutableSecretKeys() = encrypto::motion::Block128Vector::MakeZero(number_of_simd);
    bmr_wire->GetMutablePermutationBits() = encrypto::motion::BitVector<>(number_of_simd);
    bmr_wire->SetSetupIsReady();
    bmr_wire->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::bmr::Share>(wires));
}

encrypto::motion::ShareWrapper DummyBooleanGmwShare(encrypto::motion::PartyPointer& party,
                                                    std::size_t number_of_wires,
                                                    std::size_t number_of_simd) {
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto& w : wires) {
    w = register_pointer->EmplaceWire<encrypto::motion::proto::boolean_gmw::Wire>(dummy_input,
                                                                                  *backend);
    w->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::boolean_gmw::Share>(wires));
}

encrypto::motion::RunTimeStatistics EvaluateProtocol(
    encrypto::motion::PartyPointer& party, std::size_t number_of_simd, std::size_t bit_size,
    encrypto::motion::MpcProtocol protocol) {
  const std::vector<encrypto::motion::BitVector<>> temporary_bool(
      bit_size, encrypto::motion::BitVector<>(number_of_simd));

  std::vector<encrypto::motion::SecureUnsignedInteger> a(1000), b(1000);

  switch (protocol) {
    case encrypto::motion::MpcProtocol::kBooleanGmw: {
      for(int i =0; i<a.size();++i){
      a[i] = DummyBooleanGmwShare(party, bit_size, number_of_simd);
      b[i] = DummyBooleanGmwShare(party, bit_size, number_of_simd);
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kBmr: {
      for(int i=0; i<a.size();++i){
      a[i] = DummyBmrShare(party, bit_size, number_of_simd);
      b[i] = DummyBmrShare(party, bit_size, number_of_simd);
      }
      break;
    }
    case encrypto::motion::MpcProtocol::kArithmeticGmw: {
        for(int i =0; i<a.size();++i){
          a[i] = DummyArithmeticGmwShare<std::uint32_t>(party, bit_size, number_of_simd);
          b[i] = DummyArithmeticGmwShare<std::uint32_t>(party, bit_size, number_of_simd);
        }
        break;
    }
    default:
      throw std::invalid_argument("Invalid MPC protocol");
  }

  for (int i = 0; i < a.size(); ++i) {
  a[i] * b[i];
  }

  party->Run();
  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}