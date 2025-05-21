# Customer Portal Integration Guide

This document provides instructions for integrating with the customer self-service portal functionality using the SubInc backend.

## Overview

The SubInc backend provides customer portal functionality by leveraging Stripe's Customer Portal. This allows your customers to:

1. Manage their subscriptions
2. Update payment methods
3. View and download invoices
4. Monitor usage

## Prerequisites

- Stripe account with Customer Portal enabled
- Stripe API keys configured in SubInc backend
- Customers must have Stripe Customer IDs stored in the billing_methods table

## API Endpoints

The customer portal can be accessed through the following endpoints:

| Endpoint | Description |
|----------|-------------|
| `/billing-management/payments/customer-portal` | Main customer portal access |
| `/billing-management/payments/customer-portal/subscriptions` | Subscription management section |
| `/billing-management/payments/customer-portal/payment-methods` | Payment method management section |
| `/billing-management/payments/customer-portal/invoices` | Invoice viewing section |
| `/billing-management/payments/customer-portal/usage` | Usage monitoring section |

## Required Parameters

All customer portal endpoints accept the following query parameters:

- `account_id` (required): The billing account ID for the customer
- `return_url` (optional): The URL to return to after the customer is done with the portal (defaults to "/")

## Example Usage

### Frontend Integration

```javascript
// Example React component for integrating with the customer portal
function CustomerPortalButton({ accountId, section = "" }) {
  const [isLoading, setIsLoading] = useState(false);
  
  const openPortal = async () => {
    setIsLoading(true);
    try {
      // Determine which endpoint to use based on the section
      let endpoint = '/api/billing-management/payments/customer-portal';
      if (section) {
        endpoint = `${endpoint}/${section}`;
      }
      
      // Call the backend API
      const response = await fetch(`${endpoint}?account_id=${accountId}&return_url=${window.location.href}`);
      const data = await response.json();
      
      // Redirect to the Stripe portal URL
      if (data.url) {
        window.location.href = data.url;
      }
    } catch (error) {
      console.error('Error opening customer portal:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <button 
      onClick={openPortal} 
      disabled={isLoading} 
      className="portal-button"
    >
      {isLoading ? 'Loading...' : 'Manage Billing'}
    </button>
  );
}
```

### Backend Authentication

The customer portal endpoints use the "payment-method" RBAC permission with "read" access. Make sure your authenticated users have this permission to access the portal.

## Customizing the Stripe Customer Portal

You can customize the appearance and functionality of the Stripe Customer Portal through your Stripe Dashboard. Navigate to:

1. Settings > Customer Portal in your Stripe Dashboard
2. Customize the branding, features, and allowed actions
3. Set up products and pricing that will be displayed to customers

## Troubleshooting

### Common Issues

1. **"Customer not found in Stripe" error**
   - Ensure the account has a Stripe customer ID stored in the billing_methods table
   - Check that the `account_id` parameter is correct

2. **Stripe API key issues**
   - Verify that Stripe API keys are correctly configured in the SubInc backend
   - Check that the tenant has the proper Stripe configuration

3. **Return URL problems**
   - Ensure the `return_url` is a valid URL with proper encoding
   - For security reasons, some return URLs may be rejected by Stripe

## Security Considerations

- The customer portal uses Stripe's secure portal, which handles all sensitive payment information
- SubInc never stores full payment details, only tokens and references
- All portal sessions are time-limited and expire automatically
- All portal activities are logged for audit purposes

## Next Steps

After integrating the customer portal, consider:

1. Setting up webhook handlers to listen for Stripe events
2. Creating a custom dashboard to display billing information before redirecting to Stripe
3. Implementing notifications for important billing events 