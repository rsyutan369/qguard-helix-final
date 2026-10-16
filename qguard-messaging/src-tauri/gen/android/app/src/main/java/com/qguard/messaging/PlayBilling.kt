package com.qguard.messaging

import android.content.Context
import com.android.billingclient.api.AcknowledgePurchaseParams
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingClientStateListener
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.BillingResult
import com.android.billingclient.api.PendingPurchasesParams
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase
import com.android.billingclient.api.PurchasesUpdatedListener
import com.android.billingclient.api.QueryProductDetailsParams
import com.android.billingclient.api.QueryPurchasesParams
import org.json.JSONArray
import org.json.JSONObject

/**
 * Google Play Billing bridge for the QGuard Messaging paywall.
 *
 * Called from Rust over JNI (src-tauri/src/commands/billing.rs). All entry
 * points are static, thread-safe, and non-blocking: they kick asynchronous
 * Billing Library work and publish results into a JSON state blob the Rust
 * side polls with getStateJson(). Purchases are NEVER trusted here — the
 * frontend forwards the purchase token to the backend, which verifies it with
 * the Google Play Developer API before unlocking anything. Acknowledgement is
 * performed server-side after verification (the client acknowledge below is a
 * belt-and-braces fallback only for already-verified restores).
 */
object PlayBilling {
    private val lock = Any()
    private var client: BillingClient? = null

    // State published to Rust. Guarded by [lock].
    private var connectionState: String = "disconnected"
    private var lastEvent: String = ""
    private var lastEventAt: Long = 0
    private var purchases: JSONArray = JSONArray()

    private fun setEvent(event: String) {
        synchronized(lock) {
            lastEvent = event
            lastEventAt = System.currentTimeMillis()
        }
    }

    private val purchasesListener = PurchasesUpdatedListener { result, updated ->
        if (result.responseCode == BillingClient.BillingResponseCode.OK && updated != null) {
            publishPurchases(updated)
            setEvent("purchase_updated")
        } else if (result.responseCode == BillingClient.BillingResponseCode.USER_CANCELED) {
            setEvent("purchase_cancelled")
        } else {
            setEvent("purchase_error:${result.responseCode}:${result.debugMessage}")
        }
    }

    private fun publishPurchases(list: List<Purchase>) {
        val array = JSONArray()
        for (purchase in list) {
            val entry = JSONObject()
            entry.put("purchaseToken", purchase.purchaseToken)
            entry.put("orderId", purchase.orderId ?: "")
            entry.put("products", JSONArray(purchase.products))
            entry.put(
                "state",
                when (purchase.purchaseState) {
                    Purchase.PurchaseState.PURCHASED -> "purchased"
                    Purchase.PurchaseState.PENDING -> "pending"
                    else -> "unspecified"
                },
            )
            entry.put("acknowledged", purchase.isAcknowledged)
            array.put(entry)
        }
        synchronized(lock) {
            // Merge: keep previously seen purchases not present in this update
            // (queryPurchases replaces; listener updates append/overwrite).
            val merged = JSONArray()
            val seen = HashSet<String>()
            for (i in 0 until array.length()) {
                merged.put(array.getJSONObject(i))
                seen.add(array.getJSONObject(i).getString("purchaseToken"))
            }
            for (i in 0 until purchases.length()) {
                val old = purchases.getJSONObject(i)
                if (!seen.contains(old.getString("purchaseToken"))) merged.put(old)
            }
            purchases = merged
        }
    }

    private fun ensureClient(context: Context, onReady: (BillingClient) -> Unit) {
        val existing = synchronized(lock) { client }
        if (existing != null && existing.isReady) {
            onReady(existing)
            return
        }
        val fresh = existing ?: BillingClient.newBuilder(context.applicationContext)
            .setListener(purchasesListener)
            .enablePendingPurchases(
                PendingPurchasesParams.newBuilder().enableOneTimeProducts().enablePrepaidPlans().build(),
            )
            .build()
            .also { synchronized(lock) { client = it } }

        synchronized(lock) { connectionState = "connecting" }
        fresh.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) {
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    synchronized(lock) { connectionState = "connected" }
                    onReady(fresh)
                } else {
                    synchronized(lock) { connectionState = "unavailable:${result.responseCode}" }
                    setEvent("setup_error:${result.responseCode}:${result.debugMessage}")
                }
            }

            override fun onBillingServiceDisconnected() {
                synchronized(lock) { connectionState = "disconnected" }
            }
        })
    }

    /** Rust polls this. Shape mirrored in src/lib/subscription.ts. */
    @JvmStatic
    fun getStateJson(context: Context): String {
        // Opportunistically (re)connect so availability reflects reality.
        ensureClient(context) { /* connection state updated */ }
        synchronized(lock) {
            val state = JSONObject()
            state.put("available", connectionState == "connected" || connectionState == "connecting")
            state.put("platform", "android")
            state.put("connectionState", connectionState)
            state.put("lastEvent", lastEvent)
            state.put("lastEventAt", lastEventAt)
            state.put("purchases", purchases)
            return state.toString()
        }
    }

    /** Re-query owned subscriptions (Restore purchases). */
    @JvmStatic
    fun refreshPurchases(context: Context) {
        ensureClient(context) { billing ->
            val params = QueryPurchasesParams.newBuilder()
                .setProductType(BillingClient.ProductType.SUBS)
                .build()
            billing.queryPurchasesAsync(params) { result, owned ->
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    synchronized(lock) { purchases = JSONArray() }
                    publishPurchases(owned)
                    setEvent("purchases_refreshed")
                } else {
                    setEvent("refresh_error:${result.responseCode}:${result.debugMessage}")
                }
            }
        }
    }

    /**
     * Launch the subscription purchase flow.
     * accountId (Supabase user id) rides as the obfuscated account id so the
     * backend can bind the purchase to the account (anti-spoof). A non-empty
     * oldPurchaseToken turns this into an in-place plan change (prorated) so an
     * upgrade can never create a second, duplicate subscription.
     */
    @JvmStatic
    fun launchPurchase(
        context: Context,
        productId: String,
        basePlanId: String,
        accountId: String,
        oldPurchaseToken: String?,
    ) {
        // Rust passes the Application context (tao >= 0.37), never the Activity.
        val activity = CurrentActivity.resolve(context)
        if (activity == null) {
            setEvent("purchase_error:no_activity")
            return
        }
        ensureClient(context) { billing ->
            val product = QueryProductDetailsParams.Product.newBuilder()
                .setProductId(productId)
                .setProductType(BillingClient.ProductType.SUBS)
                .build()
            val query = QueryProductDetailsParams.newBuilder()
                .setProductList(listOf(product))
                .build()
            billing.queryProductDetailsAsync(query) { result, details ->
                if (result.responseCode != BillingClient.BillingResponseCode.OK || details.isEmpty()) {
                    setEvent("purchase_error:product_not_found:${result.responseCode}")
                    return@queryProductDetailsAsync
                }
                val productDetails: ProductDetails = details.first()
                val offer = productDetails.subscriptionOfferDetails
                    ?.firstOrNull { it.basePlanId == basePlanId }
                    ?: productDetails.subscriptionOfferDetails?.firstOrNull()
                if (offer == null) {
                    setEvent("purchase_error:no_offer")
                    return@queryProductDetailsAsync
                }

                val productParams = BillingFlowParams.ProductDetailsParams.newBuilder()
                    .setProductDetails(productDetails)
                    .setOfferToken(offer.offerToken)
                    .build()
                val flowBuilder = BillingFlowParams.newBuilder()
                    .setProductDetailsParamsList(listOf(productParams))
                    .setObfuscatedAccountId(accountId)
                if (!oldPurchaseToken.isNullOrEmpty()) {
                    flowBuilder.setSubscriptionUpdateParams(
                        BillingFlowParams.SubscriptionUpdateParams.newBuilder()
                            .setOldPurchaseToken(oldPurchaseToken)
                            .setSubscriptionReplacementMode(
                                BillingFlowParams.SubscriptionUpdateParams.ReplacementMode.CHARGE_PRORATED_PRICE,
                            )
                            .build(),
                    )
                }

                // launchBillingFlow must run on the UI thread.
                activity.runOnUiThread {
                    val launch = billing.launchBillingFlow(activity, flowBuilder.build())
                    if (launch.responseCode != BillingClient.BillingResponseCode.OK) {
                        setEvent("purchase_error:launch:${launch.responseCode}:${launch.debugMessage}")
                    } else {
                        setEvent("purchase_flow_started")
                    }
                }
            }
        }
    }

    /**
     * Fallback acknowledge for restored purchases the backend has already
     * verified (server-side acknowledge is the primary path).
     */
    @JvmStatic
    fun acknowledgePurchase(context: Context, purchaseToken: String) {
        ensureClient(context) { billing ->
            val params = AcknowledgePurchaseParams.newBuilder()
                .setPurchaseToken(purchaseToken)
                .build()
            billing.acknowledgePurchase(params) { result ->
                setEvent("acknowledge:${result.responseCode}")
            }
        }
    }
}
