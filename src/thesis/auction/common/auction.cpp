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

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct AuctionContext
{
  std::vector<mo::ShareWrapper> bids_price, bids_quantity, offer_price, offer_quantity;
  mo::ShareWrapper full_zero, zero, one, clearing_price;
  std::uint32_t price_range;
};

mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer &party, std::size_t input_size,
                                       mo::MpcProtocol protocol)
{
  std::uint32_t zero_help = 0;
  std::uint32_t one_help = 1;
  std::uint32_t price_range = 100;

  mo::ShareWrapper clearing_price;
  clearing_price = party->In<mo::MpcProtocol::kArithmeticGmw>(zero_help, 0);

  auto party_id = party->GetConfiguration()->GetMyId();

  std::vector<std::uint32_t> help(input_size, 5);
  std::vector<mo::ShareWrapper> bids_price, bids_quantity, offer_price, offer_quantity;

  for (std::size_t i = 0; i < input_size; i++)
  {
    bids_price = party->In<mo::MpcProtocol::kArithmeticGmw>(help[i], 0);
    bids_quantity = party->In<mo::MpcProtocol::kArithmeticGmw>(help[i], 0);
    offers_price = party->In<mo::MpcProtocol::kArithmeticGmw>(help[i], 0);
    offers_quantity = party->In<mo::MpcProtocol::kArithmeticGmw>(help[i], 0);
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
  AuctionContext context{bids_price, bids_quantity, offers_price, offers_quantity, full_zero, zero, one, clearing_price, price_range};
  CreateAuctionCircuit(&context);
  // Constructs an output gate for each bin.
  context.clearing_price = context.clearing_price.Out();
  party->Run();
  // Converts the outputs to integers.
  std::uint32_t result = context.clearing_price.As<std::uint32_t>();
  std::cout << "Market Clearing Price: " << output << std::endl;

  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
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
void CreateAuctionCircuit(PsiContext *context)
{

  mo::ShareWrapper id_match;
  mo::ShareWrapper keep;
  mo::ShareWrapper offer_sum, bid_sum, diff, min_diff;

  for (std::size_t i = 0; i < context.price_range; i++)
  {
    for (std::size_t t = 0; t < context.offer_price.size(); t++)
    {
      comp =
          (mo::SecureUnsignedInteger(context->offers_price.Convert<mo::MpcProtocol::kBooleanGmw>()) >
           mo::SecureUnsignedInteger(indices[i]));
      keep = prepare_keep(keep, context->full_zero);
      offer_sum = offer_sum + keep * context->offers_quantity[t].Get();
      comp =
          (mo::SecureUnsignedInteger(context->bids_price.Convert<mo::MpcProtocol::kBooleanGmw>()) >
           mo::SecureUnsignedInteger(indices[i]));
      keep = prepare_keep(keep, context->full_zero);
      bids_sum = bids_sum + keep * context->bids_quantity[t].Get();
    }
    diff = offer_sum - bid_sum;
    if (i == 0)
    {
      min_diff = diff;
    }

    le = (mo::SecureUnsignedInteger(min_diff) >
          mo::SecureUnsignedInteger(diff));
    ge = (mo::SecureUnsignedInteger(diff) >= mo::SecureUnsignedInteger(min_diff));
    ge = prepare_keep(ge, context.full_zero);
    le = prepare_keep(le, context.full_zero);
    context.clearing_price = ge * context.clearing_price + le * indices[i];
    min_diff = ge * min_diff + le * diff;
  }
}
