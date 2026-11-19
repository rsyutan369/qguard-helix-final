package com.qguard.messaging

import android.content.Context
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
 * Google Play Billing bridge for QGuard Messaging (Play Billing Library 8).
 *
 * Called from Rust over JNI (src-tauri/src/commands/billing.rs). Every entry
 * point is static, thread-safe and non-blocking: it starts asynchronous Billing
 * Library work and publishes the outcome into a JSON state blob that Rust polls
 * with getStateJson(). Each published outcome carries an increasing `seq`, so
 * the frontend can tell a new result from one it has already handled.
 *
 * NOTHING here grants access. The purchase token is forwarded to the QGuard
 * backend, which verifies it with the Google Play Developer API, records it,
 * acknowledges it server-side, and only then computes the account's
 * entitlements. The app never acknowledges, never trusts a purchase callback,
 * and never treats a PENDING purchase as a subscription.
 *
 * Only the base-plan offer of a product is ever purchased: the catalog has no
 * free trial and no introductory offer (Qguard_Wiki/GooglePlay_Billing §1), so
 * a promotional offer configured by mistake in Play Console is never sold.
 */
object PlayBilling {
    private val lock = Any()
    private var client: BillingClient? = null

    // Published state. Guarded by [lock].
    private var connectionState: String = "disconnected"
    private var seq: Long = 0
    private var lastEvent: String = ""
    private var lastEventAt: Long = 0
    private var lastResult: JSONObject = JSONObject()
    private var purchases: JSONArray = JSONArray()
    private var products: JSONArray = JSONArray()
    private var unavailableProducts: JSONArray = JSONArray()
    private val productCache = HashMap<String, ProductDetails>()

    /** Billing response → stable status string the frontend understands. */
    private fun statusOf(code: Int): String = when (code) {
        BillingClient.BillingResponseCode.OK -> "ok"
        BillingClient.BillingResponseCode.USER_CANCELED -> "cancelled"
        BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE,
        BillingClient.BillingResponseCode.SERVICE_DISCONNECTED,
        BillingClient.BillingResponseCode.NETWORK_ERROR -> "network"
        BillingClient.BillingResponseCode.BILLING_UNAVAILABLE,
        BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED -> "billing_unavailable"
        BillingClient.BillingResponseCode.ITEM_UNAVAILABLE -> "product_unavailable"
        BillingClient.BillingResponseCode.DEVELOPER_ERROR -> "invalid_request"
        BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED -> "already_owned"
        BillingClient.BillingResponseCode.ITEM_NOT_OWNED -> "not_owned"
        else -> "error"
    }

    /** Record an outcome. `action` names what produced it (purchase, refresh, products, setup). */
    private fun publish(action: String, status: String, code: Int, detail: String) {
        synchronized(lock) {
            seq += 1
            lastEvent = "$action:$status"
            lastEventAt = System.currentTimeMillis()
            lastResult = JSONObject()
                .put("seq", seq)
                .put("action", action)
                .put("status", status)
                .put("code", code)
                // debugMessage is developer text from Play; keep it short.
                .put("detail", detail.take(200))
                .put("at", lastEventAt)
        }
    }

    private fun publish(action: String, result: BillingResult) =
        publish(action, statusOf(result.responseCode), result.responseCode, result.debugMessage)

    private val purchasesListener = PurchasesUpdatedListener { result, updated ->
        if (result.responseCode == BillingClient.BillingResponseCode.OK && updated != null) {
            mergePurchases(updated, replace = false)
            // A PENDING purchase is reported as such — never as success.
            val pending = updated.any { it.purchaseState == Purchase.PurchaseState.PENDING }
            publish("purchase", if (pending) "pending" else "purchased", result.responseCode, "")
        } else {
            publish("purchase", result)
        }
    }

    private fun purchaseJson(purchase: Purchase): JSONObject = JSONObject()
        .put("purchaseToken", purchase.purchaseToken)
        .put("orderId", purchase.orderId ?: "")
        .put("products", JSONArray(purchase.products))
        .put(
            "state",
            when (purchase.purchaseState) {
                Purchase.PurchaseState.PURCHASED -> "purchased"
                Purchase.PurchaseState.PENDING -> "pending"
                else -> "unspecified"
            },
        )
        .put("acknowledged", purchase.isAcknowledged)
        .put("autoRenewing", purchase.isAutoRenewing)
        .put("accountId", purchase.accountIdentifiers?.obfuscatedAccountId ?: "")
        .put("purchaseTime", purchase.purchaseTime)

    private fun mergePurchases(list: List<Purchase>, replace: Boolean) {
        synchronized(lock) {
            val merged = JSONArray()
            val seen = HashSet<String>()
            for (purchase in list) {
                merged.put(purchaseJson(purchase))
                seen.add(purchase.purchaseToken)
            }
            if (!replace) {
                for (i in 0 until purchases.length()) {
                    val old = purchases.getJSONObject(i)
                    if (!seen.contains(old.getString("purchaseToken"))) merged.put(old)
                }
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
            // Billing Library 8: the client re-establishes a dropped service
            // connection itself on the next call.
            .enableAutoServiceReconnection()
            .build()
            .also { synchronized(lock) { client = it } }

        synchronized(lock) { connectionState = "connecting" }
        fresh.startConnection(object : BillingClientStateListener {
            override fun onBillingSetupFinished(result: BillingResult) {
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    synchronized(lock) { connectionState = "connected" }
                    onReady(fresh)
                } else {
                    synchronized(lock) { connectionState = "unavailable:${statusOf(result.responseCode)}" }
                    publish("setup", result)
                }
            }

            override fun onBillingServiceDisconnected() {
                synchronized(lock) { connectionState = "disconnected" }
            }
        })
    }

    /** Rust polls this. Shape mirrored in qguard-messaging/src/lib/play-billing.ts. */
    @JvmStatic
    fun getStateJson(context: Context): String {
        ensureClient(context) { /* connection state updated */ }
        synchronized(lock) {
            return JSONObject()
                .put("available", connectionState == "connected" || connectionState == "connecting")
                .put("platform", "android")
                .put("connectionState", connectionState)
                .put("seq", seq)
                .put("lastEvent", lastEvent)
                .put("lastEventAt", lastEventAt)
                .put("lastResult", lastResult)
                .put("purchases", purchases)
                .put("products", products)
                .put("unavailableProducts", unavailableProducts)
                .toString()
        }
    }

    /** End the Play connection (sign-out / app teardown). */
    @JvmStatic
    fun disconnect(context: Context) {
        synchronized(lock) {
            client?.endConnection()
            client = null
            connectionState = "disconnected"
            purchases = JSONArray()
        }
    }

    /** Re-query owned subscriptions (Restore purchases / app start). */
    @JvmStatic
    fun refreshPurchases(context: Context) {
        ensureClient(context) { billing ->
            val params = QueryPurchasesParams.newBuilder()
                .setProductType(BillingClient.ProductType.SUBS)
                .build()
            billing.queryPurchasesAsync(params) { result, owned ->
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    mergePurchases(owned, replace = true)
                }
                publish("refresh", result)
            }
        }
    }

    /** The base-plan offer of a product — never a trial or introductory offer. */
    private fun basePlanOffer(details: ProductDetails): ProductDetails.SubscriptionOfferDetails? =
        details.subscriptionOfferDetails?.firstOrNull { it.offerId == null }

    private fun productJson(details: ProductDetails): JSONObject {
        val entry = JSONObject()
            .put("productId", details.productId)
            .put("title", details.title)
            .put("name", details.name)
        val offer = basePlanOffer(details)
        val phase = offer?.pricingPhases?.pricingPhaseList?.lastOrNull()
        if (offer != null && phase != null) {
            entry.put("basePlanId", offer.basePlanId)
                .put("formattedPrice", phase.formattedPrice)
                .put("priceAmountMicros", phase.priceAmountMicros)
                .put("priceCurrencyCode", phase.priceCurrencyCode)
                .put("billingPeriod", phase.billingPeriod)
        }
        return entry
    }

    /**
     * Load localized product details (price, currency, billing period) for the
     * given comma-separated product ids. Google Play's price is what the buyer
     * is charged; the app displays it rather than a hard-coded USD figure.
     */
    @JvmStatic
    fun queryProducts(context: Context, productIdsCsv: String) {
        val ids = productIdsCsv.split(',').map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        if (ids.isEmpty()) return
        ensureClient(context) { billing ->
            val query = QueryProductDetailsParams.newBuilder()
                .setProductList(
                    ids.map {
                        QueryProductDetailsParams.Product.newBuilder()
                            .setProductId(it)
                            .setProductType(BillingClient.ProductType.SUBS)
                            .build()
                    },
                )
                .build()
            billing.queryProductDetailsAsync(query) { result, queryResult ->
                if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    val found = JSONArray()
                    val missing = JSONArray()
                    synchronized(lock) {
                        for (details in queryResult.productDetailsList) {
                            productCache[details.productId] = details
                            found.put(productJson(details))
                        }
                        for (unfetched in queryResult.unfetchedProductList) missing.put(unfetched.productId)
                        products = found
                        unavailableProducts = missing
                    }
                }
                publish("products", result)
            }
        }
    }

    /**
     * Launch the purchase flow for one product's base plan.
     * accountId is the backend-issued obfuscated account id (a SHA-256 of the
     * QGuard user id — never an email), so the server can bind the purchase to
     * the account. A non-empty oldPurchaseToken makes this an in-place plan
     * change; replacement is "upgrade" (charge the prorated difference now) or
     * "downgrade" (switch now, remaining time credited) — never a second,
     * parallel subscription.
     */
    @JvmStatic
    fun launchPurchase(
        context: Context,
        productId: String,
        accountId: String,
        oldPurchaseToken: String?,
        replacement: String?,
    ) {
        // Rust passes the Application context (tao >= 0.37), never the Activity.
        val activity = CurrentActivity.resolve(context)
        if (activity == null) {
            publish("purchase", "error", -1, "no foreground activity")
            return
        }
        ensureClient(context) { billing ->
            val launch = { details: ProductDetails ->
                val offer = basePlanOffer(details)
                if (offer == null) {
                    publish("purchase", "product_unavailable", BillingClient.BillingResponseCode.ITEM_UNAVAILABLE, "no base-plan offer for ${details.productId}")
                } else {
                    val productParams = BillingFlowParams.ProductDetailsParams.newBuilder()
                        .setProductDetails(details)
                        .setOfferToken(offer.offerToken)
                        .build()
                    val flowBuilder = BillingFlowParams.newBuilder()
                        .setProductDetailsParamsList(listOf(productParams))
                        .setObfuscatedAccountId(accountId)
                    if (!oldPurchaseToken.isNullOrEmpty()) {
                        val mode = if (replacement == "downgrade") {
                            BillingFlowParams.SubscriptionUpdateParams.ReplacementMode.WITH_TIME_PRORATION
                        } else {
                            BillingFlowParams.SubscriptionUpdateParams.ReplacementMode.CHARGE_PRORATED_PRICE
                        }
                        flowBuilder.setSubscriptionUpdateParams(
                            BillingFlowParams.SubscriptionUpdateParams.newBuilder()
                                .setOldPurchaseToken(oldPurchaseToken)
                                .setSubscriptionReplacementMode(mode)
                                .build(),
                        )
                    }
                    // launchBillingFlow must run on the UI thread.
                    activity.runOnUiThread {
                        val result = billing.launchBillingFlow(activity, flowBuilder.build())
                        if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                            publish("purchase", "flow_started", result.responseCode, "")
                        } else {
                            publish("purchase", result)
                        }
                    }
                }
            }

            val cached = synchronized(lock) { productCache[productId] }
            if (cached != null) {
                launch(cached)
                return@ensureClient
            }
            val query = QueryProductDetailsParams.newBuilder()
                .setProductList(
                    listOf(
                        QueryProductDetailsParams.Product.newBuilder()
                            .setProductId(productId)
                            .setProductType(BillingClient.ProductType.SUBS)
                            .build(),
                    ),
                )
                .build()
            billing.queryProductDetailsAsync(query) { result, queryResult ->
                val details = queryResult.productDetailsList.firstOrNull()
                if (result.responseCode != BillingClient.BillingResponseCode.OK || details == null) {
                    publish(
                        "purchase",
                        if (result.responseCode == BillingClient.BillingResponseCode.OK) "product_unavailable" else statusOf(result.responseCode),
                        result.responseCode,
                        "product $productId not available",
                    )
                } else {
                    synchronized(lock) { productCache[productId] = details }
                    launch(details)
                }
            }
        }
    }
}
