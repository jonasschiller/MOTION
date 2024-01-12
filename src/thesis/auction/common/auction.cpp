#include "auction.h"

#include <cstddef>
#include <fstream>
#include <limits>
#include <span>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/config.h"

namespace mo = encrypto::motion;
struct Bids
{
  mo::ShareWrapper price;
  mo::ShareWrapper quantity;
};

/*
Stores the input attributes of party_0 and party_1.
*/
struct Attributes
{
  std::vector<std::uint32_t> cleartext_input; // values for party_0 and categories for party_1.
  std::vector<Bids> offers;
  std::vector<Bids> bids;
} party_0, party_1;

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct AuctionContext
{
  Attributes party_0, party_1;
  mo::ShareWrapper full_zero, zero, one, clearing_price;
  std::uint32_t price_range;
  std::vector<mo::ShareWrapper> indices;
};

mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer &party, const std::string &input_file_path,
                                       mo::MpcProtocol protocol)
{
  std::uint32_t zero_help = 0;
  std::uint32_t one_help = 1;
  std::uint32_t price_range = 100;

  mo::ShareWrapper clearing_price;
  clearing_price = party->In<mo::MpcProtocol::kArithmeticGmw>(zero_help, 0);

  auto party_id = party->GetConfiguration()->GetMyId();

  // Load the Bids from File
  const auto [party_0_temp, party_1_temp] = GetFileInput(party_id, input_bids_file_path);
  party_0.cleartext_input = party_0_temp;
  party_1.cleartext_input = party_1_temp;

  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i = i + 2)
  {
    Bids party_0_bid;
    Bids party_1_bid;
    party_0_bid = party->In<mo::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input[i], 0);
    party_0_bid = party->In<mo::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input[i + 1], 0);
    party_0.bids.push_back(party_0_bid);
    party_1_bid = party->In<mo::MpcProtocol::kArithmeticGmw>(party_1.cleartext_input[i], 0);
    party_1_bid = party->In<mo::MpcProtocol::kArithmeticGmw>(party_1.cleartext_input[i + 1], 0);
    party_1.bids.push_back(party_1_bid);
  }
  // Load the Offers
  const auto [party_0_temp, party_1_temp] = GetFileInput(party_id, input_offers_file_path);
  party_0.cleartext_input = party_0_temp;
  party_1.cleartext_input = party_1_temp;

  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i = i + 2)
  {
    Bids party_0_bid;
    Bids party_1_bid;
    party_0_bid = party->In<mo::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input[i], 0);
    party_0_bid = party->In<mo::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input[i + 1], 0);
    party_0.offers.push_back(party_0_bid);
    party_1_bid = party->In<mo::MpcProtocol::kArithmeticGmw>(party_1.cleartext_input[i], 0);
    party_1_bid = party->In<mo::MpcProtocol::kArithmeticGmw>(party_1.cleartext_input[i + 1], 0);
    party_1.offers.push_back(party_1_bid);
  }

  mo::ShareWrapper full_zero =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::BitVector<>(1, false), 0);
  mo::ShareWrapper zero = party->In<mo::MpcProtocol::kArithmeticGmw>(zero_help, 0);
  mo::ShareWrapper one = party->In<mo::MpcProtocol::kArithmeticGmw>(one_help, 0);
  std::vector<mo : ShareWrapper> indices(price_range);
  for (int i = 0; i < price_range; i++)
  {
    indices[i] = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(i), 0);
  }
  AuctionContext context{party_0, party_1, full_zero, zero, one, clearing_price, price_range, indices};
  mo::SecureUnsignedInteger output = CreateAuctionCircuit(context);
  // Constructs an output gate for each bin.
  output = output.Out();
  party->Run();
  // Converts the outputs to integers.
  std::uint32_t result = output.As<std::uint32_t>();
  std::cout << "Market Clearing Price: " << output << std::endl;

  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}

/**
 * Takes inputs from file in path.
 */
std::tuple<std::vector<std::uint32_t>, std::vector<std::uint32_t>> GetFileInput(
    std::size_t party_id, const std::string &path)
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
      party_1.push_back(n); // Assigns dummy input to party_1.
    }
    else
    {
      party_0.push_back(n); // Assigns dummy input to party_0..
      party_1.push_back(n); // Assigns input values to party_1.
    }
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

/**
 * Calculates the market clearing price based on the given offers.
 * */
std::vector<mo::SecureUnsignedInteger> CreateAuctionCircuit(PsiContext context)
{
  auto party_0_offers = context.party_0.offers, party_1_offers = context.party_1.offers;
  auto party_0_bids = context.party_0.bids, party_1_bids = context.party_1.bids;
  auto indices = context.indices
                     mo::ShareWrapper id_match;
  mo::ShareWrapper keep;
  mo::ShareWrapper offer_sum, bid_sum, diff, min_diff;

  // Concatenate Offers and Bids
  party_0_offers.insert(party_0_offers.end(), party_1_offers.begin(), party_1_offers.end());
  party_0_bids.insert(party_0_bids.end(), party_1_bids.begin(), party_1_bids.end());

  for (std::size_t i = 0; i < context.price_range; i++)
  {
    for (std::size_t t = 0; t < party_0_offers.size(); t++)
    {
      comp =
          (mo::SecureUnsignedInteger(party_0_offers[t].price.Convert<mo::MpcProtocol::kBooleanGmw>()) >
           mo::SecureUnsignedInteger(indices[i]));
      keep = prepare_keep(keep, context.full_zero);
      offer_sum = offer_sum + keep * party_0_offers[t].quantity;
    }

    // Calculate Price quantity of offers below this price
    for (std::size_t t = 0; t < party_0_bids.size(); t++)
    {
      comp =
          (mo::SecureUnsignedInteger(party_0_bids[t].price.Convert<mo::MpcProtocol::kBooleanGmw>()) >
           mo::SecureUnsignedInteger(indices[i]));
      keep = prepare_keep(keep, context.full_zero);
      bid_sum = bid_sum + keep * party_0_bids[t].quantity;
    }
    diff = offer_sum - bid_sum;
    le = (mo::SecureUnsignedInteger(min_diff) >
          mo::SecureUnsignedInteger(diff));
    ge = (mo::SecureUnsignedInteger(diff) > mo::SecureUnsignedInteger(min_diff));
    ge = prepare_keep(ge, context.full_zero);
    le = prepare_keep(le, context.full_zero);
    context.clearing_price = ge * context.clearing_price + le * indices[i];
    if (i == 0)
    {
      min_diff = diff;
    }
    else
    {
      min_diff = ge * min_diff + le * diff;
    }
  }

  return context.clearing_price;
}
