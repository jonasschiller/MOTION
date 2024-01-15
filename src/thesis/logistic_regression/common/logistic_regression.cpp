#include "logistic_regression.h"

#include <cstddef>
#include <fstream>
#include <limits>
#include <span>
#include <vector>
#include <stdexcept>
#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/config.h"

// Abbreviate Namespace
namespace mo = encrypto::motion;
/*
Stores the input attributes of party_0 and party_1.
*/
struct Attributes
{
  std::vector<std::vector<std::int32_t>> cleartext_input_matrix;
  std::vector<std::int32_t> cleartext_input_vector;
  std::vector<std::vector<mo::ShareWrapper>> shared_input_matrix;
  std::vector<mo::ShareWrapper> shared_input_vector;
} party_0, party_1;

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct LogRegContext
{
  Attributes party_0, party_1;
  std::vector<mo::ShareWrapper> weights;
  mo::ShareWrapper full_zero;
};

/*
 * Runs the protocol and returns the runtime statistics.
 * First reads in the files and then calculates sum, mean, min and max
 */
mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer &party, const std::string &input_file_path,
                                       mo::MpcProtocol protocol)
{
  std::vector<mo::ShareWrapper> weights;
  std::vector<mo::ShareWrapper> results;
  // Get respective party id
  auto party_id = party->GetConfiguration()->GetMyId();
  // Load the correct input from file via file_path from command line
  const auto [party_0_temp, party_1_temp] = GetFileInput(party_id, input_file_path);
  party_0.cleartext_input_matrix = party_0_temp_matrix;
  party_1.cleartext_input_vector = party_1_temp.vector;

  // Input from Party 0 which are the features of the dataset
  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i++)
  {
    for (std::size_t t = 0; i < party_0.cleartext_input[i].size(); t++)
    {
      party_0.shared_input_matrix.push_back(
          party->In<mo::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input_matrix[i][t], 0));
    }
  }
  // Input from Party 1 which are the labels of the dataset
  for (std::size_t i = 0; i < party_1.cleartext_input.size(); i++)
  {
    party_1.shared_input_vector.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(party_1.cleartext_input_vector[i], 1));
  }
  // Preshare and instantiate the weight vector with one element per feature
  std::vector<mo::ShareWrapper> weights;
  for (std::size_t i = 0; i < party_0.cleartext_input[0].size(); i++)
  {
    weights.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(0, 0));
  }
  // Create the context for the circuit
  uint32_t zero = 0;
  mo::ShareWrapper full_zero =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::BitVector<>(1, false), 0);

  StatisticsContext context{party_0, party_1, weights, full_zero};
  // Create the circuit

  weights = CreateLogisticTrainingCircuit(context);
  // Create the output gate
  sum = sum.Out();
  party->Run();
  std::cout << "Sum " << sum.As<std::uint32_t>() << std::endl;
  party->Finish();

  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}

/*Calculates the Dot Product between a Matrix and a Vector utilizing the Dot Product Implementation by MOTION*/
std::vector<mo::ShareWrapper> dot_product(std::vector<std::vector<SecureSignedInteger>> matrix, std::vector<SecureSignedInteger> vec, std::vector<SecureSignedInteger> result)
{
  if (matrix.empty() || matrix[0].size() != vec.size())
  {
    throw std::invalid_argument("Matrix columns and vector size must match");
  }
  for (size_t i = 0; i < matrix.size(); ++i)
  {
    result[i] = mo::DotProduct(matrix[i], vec);
  }
  return result;
}

std::vector<mo::ShareWrapper> CreateLogisticTrainingCircuit(LogRegContext context)
{
  return dot_product(context.party_0.shared_input_matrix, context.party_1.shared_input_vector, context.weights);
}

/**
 * Takes inputs from file in path.
 */
std::tuple<std::vector<std::uint32_t>, std::vector<std::uint32_t>, std::vector<std::uint32_t>>
GetFileInput(std::size_t party_id, const std::string &path)
{
  std::ifstream infile;
  std::vector < std::vector<int32_t> party_0;
  std::vector<std::int32_t> party_1;
  std::uint32_t n;

  infile.open(path);
  if (!infile.is_open())
    throw std::runtime_error("Could not open Statistics File");
  std::uint32_t i = 0;
  // Matrix read in based on shape provided in first two words of file
  std::uint32_t rows, cols;
  while (infile >> n)
  {
    if (i == 0)
    {
      rows = n;
    }
    else if (i == 1)
    {
      cols = n;
    }
    else
    {
      if (party_id == 0)
      {
        party_0[(i - 2) / cols].push_back(n); // Assigns input values to party_0.
        if ((i - 2) < cols)
        {
          party_1.push_back(n); // Assigns dummy input to party_1.
        }
      }
      else
      {
        party_0.push_back(n); // Assigns dummy input to party_0..
        if ((i - 2) < cols)
        {
          party_1.push_back(n); // Assigns dummy input to party_1.
        }
      }
    }
    i++;
  }
  infile.close();
  return {party_0, party_1};
}

/**
 * Transform the boolean value in keep into an arithmetic share.
 */
mo::ShareWrapper prepare_keep(mo::ShareWrapper keep, mo::ShareWrapper full_zero)
{
  std::vector<mo::ShareWrapper> keep_concat;
  keep_concat.push_back(keep);
  for (std::size_t s = 0; s < 31; s++)
    keep_concat.push_back(full_zero);
  keep = mo::ShareWrapper::Concatenate(keep_concat);
  keep = keep.Convert<mo::MpcProtocol::kArithmeticGmw>();
  return keep;
}