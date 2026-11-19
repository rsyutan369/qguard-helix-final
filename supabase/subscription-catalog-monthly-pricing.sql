-- Existing installations: align Qguard's displayed USD list prices with PayPal.
-- Google Play regional charges are managed separately in Play Console.
UPDATE public.subscription_products AS product
SET price_amount = prices.usd
FROM (VALUES ('Basic', 8.00), ('Pro', 30.00), ('Elite', 199.00)) AS prices(tier, usd)
WHERE product.platform IN ('paypal', 'google_play')
  AND product.billing_period = 'monthly'
  AND product.currency = 'USD'
  AND product.tier = prices.tier
  AND product.price_amount IS DISTINCT FROM prices.usd;

COMMENT ON TABLE public.subscription_products IS
  'Qguard subscription products and USD list prices, with separate monthly and annual charges. Google Play checkout uses the regional base plan price returned by Google.';
