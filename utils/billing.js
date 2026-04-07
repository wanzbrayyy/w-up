const PRO_MONTHLY_PRICE = 49000;
const PRO_YEARLY_PRICE = 490000;
const PRO_STORAGE_LIMIT = 50 * 1024 * 1024 * 1024;

function getBillingPricing() {
  return {
    monthlyPrice: PRO_MONTHLY_PRICE,
    yearlyPrice: PRO_YEARLY_PRICE
  };
}

function getBillingAmount(billingCycle = 'monthly') {
  return billingCycle === 'yearly' ? PRO_YEARLY_PRICE : PRO_MONTHLY_PRICE;
}

async function activateProPlan(user, billingCycle = 'monthly') {
  const durationDays = billingCycle === 'yearly' ? 365 : 30;
  const now = Date.now();
  const currentExpiry = user.subscriptionExpiresAt ? new Date(user.subscriptionExpiresAt).getTime() : 0;
  const baseTimestamp = currentExpiry > now ? currentExpiry : now;

  user.plan = 'pro';
  user.storageLimit = PRO_STORAGE_LIMIT;
  user.subscriptionCycle = billingCycle;
  user.lastPaymentAt = new Date();
  user.subscriptionExpiresAt = new Date(baseTimestamp + durationDays * 24 * 60 * 60 * 1000);
  await user.save();

  return user.subscriptionExpiresAt;
}

module.exports = {
  PRO_STORAGE_LIMIT,
  getBillingPricing,
  getBillingAmount,
  activateProPlan
};
