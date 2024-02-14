

#include "logreg.h"

#include "algorithm/algorithm_description.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t number_of_simd,
                                                     encrypto::motion::MpcProtocol protocol)
{

  // TODO load the correct input format for the circuit both inputs are connected together as one long BitVector of required length

  std::vector<encrypto::motion::BitVector<>> data(35510,
                                                  encrypto::motion::BitVector<>(1));
  std::vector<encrypto::motion::BitVector<>> weights(10,
                                                     encrypto::motion::BitVector<>(1));
  encrypto::motion::ShareWrapper data_shared{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw
          ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(data, 0)
          : party->In<encrypto::motion::MpcProtocol::kBmr>(data, 0)};
  encrypto::motion::ShareWrapper weights_shared{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw
          ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(weights, 0)
          : party->In<encrypto::motion::MpcProtocol::kBmr>(weights, 0)};
  const auto kPathToAlgorithm{std::string(encrypto::motion::kRootDir) +
                              "/circuits/Benchmarks/logreg.bristol"};
  const auto logreg_algorithm{encrypto::motion::AlgorithmDescription::FromBristol(kPathToAlgorithm)};
  encrypto::motion::ShareWrapper input;
  std::vector<encrypto::motion::ShareWrapper> concat;
  concat.push_back(data_shared);
  concat.push_back(weights_shared);
  input = encrypto::motion::ShareWrapper::Concatenate(concat);
  const auto result{input.Evaluate(logreg_algorithm)};

  encrypto::motion::ShareWrapper output;

  output = result.Out();

  party->Run();
  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
