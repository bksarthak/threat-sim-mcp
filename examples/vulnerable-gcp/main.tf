provider "google" {
  project = "threat-sim-demo"
  region  = "us-central1"
}

# 1. Edge: Unauthenticated Cloud Function (Equivalent to a public AWS Lambda)
resource "google_cloudfunctions_function" "webhook" {
  name        = "public-webhook"
  description = "Publicly accessible HTTP function"
  runtime     = "nodejs18"

  available_memory_mb   = 128
  source_archive_bucket = google_storage_bucket.source_bucket.name
  source_archive_object = "function.zip"
  trigger_http          = true
  
  # Execution Context
  service_account_email = google_service_account.cloud_function_sa.email
}

# Threat: Making the function publicly invokable over the internet without Identity Aware Proxy (IAP) or Auth
resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = google_cloudfunctions_function.webhook.project
  region         = google_cloudfunctions_function.webhook.region
  cloud_function = google_cloudfunctions_function.webhook.name

  role   = "roles/cloudfunctions.invoker"
  member = "allUsers"
}

# 2. Compute Target: Service Account Execution Role
resource "google_service_account" "cloud_function_sa" {
  account_id   = "cf-webhook-sa"
  display_name = "Cloud Function Service Account"
}

# 3. Transitive Pivot: Overly Permissive primitive role assignment (Privilege Escalation)
# Threat: Instead of granting least-privilege API access, the function is granted the 'Editor' primitive role.
# An RCE against the webhook allows the attacker to inherently own and mutate the entire GCP project structure.
resource "google_project_iam_binding" "project_editor" {
  project = "threat-sim-demo"
  role    = "roles/editor"

  members = [
    "serviceAccount:${google_service_account.cloud_function_sa.email}",
  ]
}

# (Required mock resource for the function to deploy)
resource "google_storage_bucket" "source_bucket" {
  name     = "threat-sim-cloud-function-source"
  location = "US"
  uniform_bucket_level_access = true
}
