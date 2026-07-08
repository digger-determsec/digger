/// Webhook framework — register, dispatch, track deliveries.
use crate::models::now_iso;
use crate::models::*;
use crate::storage::{Storage, StorageError};
use uuid::Uuid;

pub struct WebhookManager<'a> {
    store: &'a dyn Storage,
}

impl<'a> WebhookManager<'a> {
    pub fn new(store: &'a dyn Storage) -> Self {
        Self { store }
    }

    pub fn register(
        &self,
        org_id: &str,
        url: &str,
        events: Vec<WebhookEvent>,
    ) -> Result<Webhook, StorageError> {
        let webhook = Webhook {
            id: Uuid::new_v4().to_string(),
            org_id: org_id.to_string(),
            url: url.to_string(),
            events,
            secret: Uuid::new_v4().to_string(),
            active: true,
            created_at: now_iso(),
        };
        let val = serde_json::to_value(&webhook)?;
        self.store.write_json("webhooks", &webhook.id, &val)?;
        Ok(webhook)
    }

    pub fn get(&self, id: &str) -> Result<Webhook, StorageError> {
        let val = self.store.read_json("webhooks", id)?;
        Ok(serde_json::from_value(val)?)
    }

    pub fn list_for_org(&self, org_id: &str) -> Vec<Webhook> {
        self.store
            .list_all_json("webhooks")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Webhook>(v).ok())
            .filter(|w| w.org_id == org_id && w.active)
            .collect()
    }

    pub fn deactivate(&self, id: &str) -> Result<Webhook, StorageError> {
        let mut webhook = self.get(id)?;
        webhook.active = false;
        let val = serde_json::to_value(&webhook)?;
        self.store.write_json("webhooks", &webhook.id, &val)?;
        Ok(webhook)
    }

    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        self.store.delete("webhooks", id)
    }

    pub fn dispatch_event(
        &self,
        org_id: &str,
        event: WebhookEvent,
        payload: serde_json::Value,
    ) -> Result<Vec<WebhookDelivery>, StorageError> {
        self.dispatch_event_signed(org_id, event, payload, None)
    }

    pub fn dispatch_event_signed(
        &self,
        org_id: &str,
        event: WebhookEvent,
        payload: serde_json::Value,
        signature: Option<String>,
    ) -> Result<Vec<WebhookDelivery>, StorageError> {
        let webhooks = self.list_for_org(org_id);
        let mut deliveries = Vec::new();
        for webhook in webhooks {
            if webhook.events.contains(&event) {
                let delivery = WebhookDelivery {
                    id: Uuid::new_v4().to_string(),
                    webhook_id: webhook.id.clone(),
                    event: event.clone(),
                    payload: payload.clone(),
                    status: DeliveryStatus::Pending,
                    attempt: 0,
                    max_attempts: 3,
                    response_code: None,
                    error: None,
                    created_at: now_iso(),
                    delivered_at: None,
                    next_retry_at: None,
                    signature: signature.clone(),
                };
                let delivery_key = format!("delivery_{}", delivery.id);
                let val = serde_json::to_value(&delivery)?;
                let _ = self.store.write_json("webhooks", &delivery_key, &val);
                deliveries.push(delivery);
            }
        }
        Ok(deliveries)
    }

    pub fn mark_delivered(
        &self,
        delivery_id: &str,
        response_code: u16,
    ) -> Result<(), StorageError> {
        let key = format!("delivery_{}", delivery_id);
        let val = self.store.read_json("webhooks", &key)?;
        let mut delivery: WebhookDelivery = serde_json::from_value(val)?;
        delivery.status = DeliveryStatus::Delivered;
        delivery.response_code = Some(response_code);
        delivery.delivered_at = Some(now_iso());
        let val = serde_json::to_value(&delivery)?;
        self.store.write_json("webhooks", &key, &val)?;
        Ok(())
    }

    pub fn mark_failed(
        &self,
        delivery_id: &str,
        error: String,
    ) -> Result<WebhookDelivery, StorageError> {
        let key = format!("delivery_{}", delivery_id);
        let val = self.store.read_json("webhooks", &key)?;
        let mut delivery: WebhookDelivery = serde_json::from_value(val)?;
        delivery.attempt += 1;
        if delivery.attempt >= delivery.max_attempts {
            delivery.status = DeliveryStatus::Failed;
        } else {
            delivery.status = DeliveryStatus::Retrying;
            let retry_secs = 2u64.pow(delivery.attempt - 1) * 60;
            delivery.next_retry_at = Some(now_iso_secs(retry_secs));
        }
        delivery.error = Some(error);
        let val = serde_json::to_value(&delivery)?;
        self.store.write_json("webhooks", &key, &val)?;
        Ok(delivery)
    }
}
