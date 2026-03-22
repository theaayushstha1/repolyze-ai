#!/bin/bash
# RepolyzeAI Deployment Script
# Usage: ./deploy.sh [frontend|backend|all]

set -e

PROJECT_ID="repolyze-ai"
REGION="us-central1"
BACKEND_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/repolyze-ai/backend"

deploy_frontend() {
    echo "=== Deploying Frontend to Vercel ==="
    cd frontend
    npx vercel --prod
    cd ..
    echo "Frontend deployed!"
}

deploy_backend() {
    echo "=== Deploying Backend to Cloud Run ==="

    # Build and push Docker image
    echo "Building Docker image..."
    cd backend
    gcloud builds submit --tag "$BACKEND_IMAGE" --project "$PROJECT_ID"

    # Deploy to Cloud Run
    echo "Deploying to Cloud Run..."
    gcloud run deploy repolyze-api \
        --image "$BACKEND_IMAGE" \
        --platform managed \
        --region "$REGION" \
        --project "$PROJECT_ID" \
        --allow-unauthenticated \
        --memory 2Gi \
        --cpu 2 \
        --timeout 300 \
        --set-env-vars "GCP_PROJECT_ID=$PROJECT_ID" \
        --max-instances 10 \
        --min-instances 0

    cd ..
    echo "Backend deployed!"

    # Get URL
    URL=$(gcloud run services describe repolyze-api \
        --region "$REGION" \
        --project "$PROJECT_ID" \
        --format "value(status.url)")
    echo "Backend URL: $URL"
}

case "${1:-all}" in
    frontend) deploy_frontend ;;
    backend)  deploy_backend ;;
    all)
        deploy_frontend
        deploy_backend
        ;;
    *)
        echo "Usage: ./deploy.sh [frontend|backend|all]"
        exit 1
        ;;
esac
