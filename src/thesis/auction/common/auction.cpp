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
#include "secure_type/secure_signed_integer.h"
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
  std::vector<mo::ShareWrapper> bids_price, bids_quantity, offers_price, offers_quantity, indices;
  mo::ShareWrapper full_zero, zero, clearing_price;
  std::int32_t price_range;
};

mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer &party, std::size_t input_size,
                                       mo::MpcProtocol protocol)
{
  std::int32_t zero_help = 0;
  std::int32_t one_help = 1;
  std::int32_t price_range = 10;

  mo::ShareWrapper clearing_price;
  clearing_price = party->In<mo::MpcProtocol::kArithmeticGmw>(zero_help, 0);

  auto party_id = party->GetConfiguration()->GetMyId();

  std::vector<std::int32_t> help(input_size, 5);
  std::vector<mo::ShareWrapper> bids_price, bids_quantity, offers_price, offers_quantity;

  for (std::size_t i = 0; i < input_size; i++)
  {
    bids_price.push_back(party->In<mo::MpcProtocol::kArithmeticGmw>(help[i], 0));
    bids_quantity.push_back(party->In<mo::MpcProtocol::kArithmeticGmw>(help[i], 0));
    offers_price.push_back(party->In<mo::MpcProtocol::kArithmeticGmw>(help[i], 0));
    offers_quantity.push_back(party->In<mo::MpcProtocol::kArithmeticGmw>(help[i], 0));
  }

  mo::ShareWrapper full_zero =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::BitVector<>(1, false), 0);
  mo::ShareWrapper zero = party->In<mo::MpcProtocol::kArithmeticGmw>(zero_help, 0);
  std::vector<mo::ShareWrapper> indices;
  for (int i = 0; i < price_range; i++)
  {
    indices.push_back(party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(i), 0));
  }
  AuctionContext context{bids_price, bids_quantity, offers_price, offers_quantity, indices, full_zero, zero, clearing_price, price_range};
  CreateAuctionCircuit(&context);
  // Constructs an output gate for each bin.
  mo::SecureSignedInteger clearing_out = mo::SecureSignedInteger(context.clearing_price).Out();
  std::vector<mo::SecureSignedInteger> out(price_range);
  party->Run();
  // Converts the outputs to integers.
  std::int32_t result = clearing_out.As<std::int32_t>();
  std::cout << "Market Clearing Price: " << result << std::endl;
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
void CreateAuctionCircuit(AuctionContext *context)
{

  mo::ShareWrapper comp;
  mo::ShareWrapper keep;
  mo::ShareWrapper offer_sum, bids_sum, diff, min_diff, le, ge, eq;

  for (std::size_t i = 0; i < context->price_range; i++)
  {
    for (std::size_t t = 0; t < context->offers_price.size(); t++)
    {
      comp =
          (mo::SecureUnsignedInteger(context->offers_price[t].Convert<mo::MpcProtocol::kBooleanGmw>()) >
           mo::SecureUnsignedInteger(context->indices[i]));
      eq =
          (mo::SecureUnsignedInteger(context->offers_price[t].Convert<mo::MpcProtocol::kBooleanGmw>()) ==
           mo::SecureUnsignedInteger(context->indices[i]));
      keep = prepare_keep(comp | eq, context->full_zero);
      if (t == 0)
      {
        offer_sum = keep * context->offers_quantity[t].Get();
      }
      else
      {
        offer_sum = offer_sum + keep * context->offers_quantity[t].Get();
      }
      comp =
          (mo::SecureUnsignedInteger(context->bids_price[t].Convert<mo::MpcProtocol::kBooleanGmw>()) >
           mo::SecureUnsignedInteger(context->indices[i]));
      eq =
          (mo::SecureUnsignedInteger(context->bids_price[t].Convert<mo::MpcProtocol::kBooleanGmw>()) >
           mo::SecureUnsignedInteger(context->indices[i]));
      keep = prepare_keep(comp | eq, context->full_zero);

      if (t == 0)
      {
        bids_sum = keep * context->bids_quantity[t].Get();
      }
      else
      {
        bids_sum = bids_sum + keep * context->bids_quantity[t].Get();
      }
    }
    diff = bids_sum - offer_sum;
    if (i == 0)
    {
      min_diff = diff;
    }

    le = (mo::SecureUnsignedInteger(min_diff.Convert<mo::MpcProtocol::kBooleanGmw>()) >
          mo::SecureUnsignedInteger(diff.Convert<mo::MpcProtocol::kBooleanGmw>()));
    ge = (mo::SecureUnsignedInteger(diff.Convert<mo::MpcProtocol::kBooleanGmw>()) > mo::SecureUnsignedInteger(min_diff.Convert<mo::MpcProtocol::kBooleanGmw>()));
    eq = (mo::SecureUnsignedInteger(diff.Convert<mo::MpcProtocol::kBooleanGmw>()) == mo::SecureUnsignedInteger(min_diff.Convert<mo::MpcProtocol::kBooleanGmw>()));
    ge = prepare_keep(ge, context->full_zero);
    le = prepare_keep(le, context->full_zero);
    eq = prepare_keep(eq, context->full_zero);
    context->clearing_price = ge * context->clearing_price + le * context->indices[i].Convert<mo::MpcProtocol::kArithmeticGmw>() + eq * context->clearing_price;
    min_diff = ge * min_diff + le * diff + eq * diff;
  }
}
