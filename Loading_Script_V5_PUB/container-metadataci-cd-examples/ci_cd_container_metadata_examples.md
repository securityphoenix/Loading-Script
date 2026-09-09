# CI/CD Container Metadata Integration Examples

This document provides ready-to-use CI/CD pipeline configurations for capturing container metadata and uploading enriched vulnerability scans to Phoenix Security.

## Table of Contents

1. [GitHub Actions](#github-actions)
2. [GitLab CI](#gitlab-ci)
3. [Jenkins](#jenkins)
4. [Azure DevOps](#azure-devops)
5. [CircleCI](#circleci)
6. [Bitbucket Pipelines](#bitbucket-pipelines)

---

## GitHub Actions

### Complete Workflow Example

```yaml
# .github/workflows/container-security.yml
name: Container Build & Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build-scan-upload:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      security-events: write
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract metadata for Docker
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=sha,prefix=
            type=ref,event=branch
            type=semver,pattern={{version}}
      
      - name: Build and push Docker image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
      
      # =====================================================
      # PHOENIX METADATA CAPTURE & SECURITY SCANNING
      # =====================================================
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y jq
          # Install yq for YAML processing
          sudo wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
          sudo chmod +x /usr/local/bin/yq
      
      - name: Download Phoenix metadata capture script
        run: |
          curl -sL https://raw.githubusercontent.com/your-org/phoenix-tools/main/capture_container_metadata.sh -o capture_metadata.sh
          chmod +x capture_metadata.sh
      
      - name: Capture container metadata
        run: |
          ./capture_metadata.sh "${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:sha-${{ github.sha }}" \
            -o container_metadata.yaml
      
      - name: Run Trivy vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: '${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:sha-${{ github.sha }}'
          format: 'json'
          output: 'trivy_results.json'
          severity: 'CRITICAL,HIGH,MEDIUM,LOW'
      
      - name: Extract Phoenix tags from metadata
        run: |
          yq '.phoenix_tags' container_metadata.yaml > phoenix_tags.yaml
          echo "Generated Phoenix tags:"
          cat phoenix_tags.yaml
      
      - name: Upload to Phoenix Security
        env:
          PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
          PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
          PHOENIX_API_URL: ${{ secrets.PHOENIX_API_URL }}
        run: |
          python phoenix_multi_scanner_enhanced.py \
            --file trivy_results.json \
            --scanner trivy \
            --assessment "Container Scan - ${{ github.repository }} - ${{ github.sha }}" \
            --tag-file phoenix_tags.yaml \
            --enable-batching
      
      - name: Upload metadata as artifact
        uses: actions/upload-artifact@v4
        with:
          name: container-metadata
          path: |
            container_metadata.yaml
            trivy_results.json
            phoenix_tags.yaml
```

### Minimal GitHub Actions Example

```yaml
# .github/workflows/security-scan-simple.yml
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Scan with Trivy
        run: |
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest image --format json -o /tmp/results.json myapp:${{ github.sha }}
      
      - name: Generate metadata tags
        run: |
          cat > tags.yaml << EOF
          - key: "image-name"
            value: "myapp"
          - key: "commit-sha"
            value: "${{ github.sha }}"
          - key: "branch"
            value: "${{ github.ref_name }}"
          - key: "ci-system"
            value: "github-actions"
          - key: "pipeline-id"
            value: "${{ github.run_id }}"
          - key: "build-date"
            value: "$(date +%Y-%m-%d)"
          EOF
      
      - name: Upload to Phoenix
        env:
          PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
          PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
        run: |
          python phoenix_multi_scanner_enhanced.py \
            --file /tmp/results.json \
            --scanner trivy \
            --tag-file tags.yaml
```

---

## GitLab CI

### Complete Pipeline Example

```yaml
# .gitlab-ci.yml
stages:
  - build
  - scan
  - upload

variables:
  DOCKER_TLS_CERTDIR: "/certs"
  IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

build:
  stage: build
  image: docker:24.0
  services:
    - docker:24.0-dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $IMAGE_TAG .
    - docker push $IMAGE_TAG
  artifacts:
    reports:
      dotenv: build.env

capture_metadata:
  stage: scan
  image: docker:24.0
  services:
    - docker:24.0-dind
  before_script:
    - apk add --no-cache bash jq curl
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker pull $IMAGE_TAG
  script:
    # Generate metadata inline (simplified version)
    - |
      cat > container_metadata.yaml << EOF
      metadata_version: "1.0"
      capture_timestamp: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      
      container:
        image_full_ref: "$IMAGE_TAG"
        registry: "$CI_REGISTRY"
        repository: "$CI_PROJECT_PATH"
        image_name: "$CI_PROJECT_NAME"
        tag: "$CI_COMMIT_SHA"
        digest: "$(docker inspect --format='{{index .RepoDigests 0}}' $IMAGE_TAG | cut -d@ -f2)"
        created: "$(docker inspect --format='{{.Created}}' $IMAGE_TAG)"
        architecture: "$(docker inspect --format='{{.Architecture}}' $IMAGE_TAG)"
        os: "$(docker inspect --format='{{.Os}}' $IMAGE_TAG)"
      
      source:
        repository_url: "$CI_PROJECT_URL"
        commit_sha: "$CI_COMMIT_SHA"
        commit_sha_short: "$CI_COMMIT_SHORT_SHA"
        commit_message: "$CI_COMMIT_MESSAGE"
        commit_author: "$CI_COMMIT_AUTHOR"
        branch: "$CI_COMMIT_REF_NAME"
      
      pipeline:
        ci_system: "gitlab-ci"
        pipeline_id: "$CI_PIPELINE_ID"
        pipeline_url: "$CI_PIPELINE_URL"
        job_id: "$CI_JOB_ID"
        trigger_type: "$CI_PIPELINE_SOURCE"
        trigger_actor: "$GITLAB_USER_LOGIN"
      
      phoenix_tags:
        - key: "image-name"
          value: "$CI_PROJECT_NAME"
        - key: "image-tag"
          value: "$CI_COMMIT_SHA"
        - key: "source-repo"
          value: "$CI_PROJECT_PATH"
        - key: "commit-sha"
          value: "$CI_COMMIT_SHORT_SHA"
        - key: "branch"
          value: "$CI_COMMIT_REF_NAME"
        - key: "ci-system"
          value: "gitlab-ci"
        - key: "pipeline-id"
          value: "$CI_PIPELINE_ID"
        - key: "build-date"
          value: "$(date +%Y-%m-%d)"
      EOF
    - cat container_metadata.yaml
  artifacts:
    paths:
      - container_metadata.yaml
    expire_in: 1 week

trivy_scan:
  stage: scan
  image: 
    name: aquasec/trivy:latest
    entrypoint: [""]
  services:
    - docker:24.0-dind
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_VERIFY: 1
  before_script:
    - trivy --version
  script:
    - trivy image --format json --output trivy_results.json $IMAGE_TAG
  artifacts:
    paths:
      - trivy_results.json
    expire_in: 1 week

upload_to_phoenix:
  stage: upload
  image: python:3.11-slim
  dependencies:
    - capture_metadata
    - trivy_scan
  before_script:
    - pip install requests pyyaml
  script:
    # Extract phoenix_tags from metadata
    - |
      python3 << 'EOF'
      import yaml
      with open('container_metadata.yaml') as f:
          data = yaml.safe_load(f)
      with open('phoenix_tags.yaml', 'w') as f:
          yaml.dump(data.get('phoenix_tags', []), f)
      EOF
    # Upload to Phoenix
    - |
      python phoenix_multi_scanner_enhanced.py \
        --file trivy_results.json \
        --scanner trivy \
        --assessment "GitLab CI - $CI_PROJECT_NAME - $CI_COMMIT_SHORT_SHA" \
        --tag-file phoenix_tags.yaml
  only:
    - main
    - develop
```

---

## Jenkins

### Jenkinsfile Example

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        REGISTRY = 'your-registry.com'
        IMAGE_NAME = 'myapp'
        IMAGE_TAG = "${REGISTRY}/${IMAGE_NAME}:${GIT_COMMIT}"
        PHOENIX_CREDENTIALS = credentials('phoenix-api-credentials')
    }
    
    stages {
        stage('Build') {
            steps {
                script {
                    docker.build(IMAGE_TAG)
                    docker.withRegistry("https://${REGISTRY}", 'registry-credentials') {
                        docker.image(IMAGE_TAG).push()
                    }
                }
            }
        }
        
        stage('Capture Metadata') {
            steps {
                script {
                    def metadata = """
metadata_version: "1.0"
capture_timestamp: "${new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))}"

container:
  image_full_ref: "${IMAGE_TAG}"
  registry: "${REGISTRY}"
  repository: "${IMAGE_NAME}"
  image_name: "${IMAGE_NAME}"
  tag: "${GIT_COMMIT}"

source:
  repository_url: "${GIT_URL}"
  commit_sha: "${GIT_COMMIT}"
  commit_sha_short: "${GIT_COMMIT.take(7)}"
  branch: "${GIT_BRANCH}"

pipeline:
  ci_system: "jenkins"
  pipeline_id: "${BUILD_NUMBER}"
  pipeline_url: "${BUILD_URL}"
  job_id: "${JOB_NAME}"
  trigger_type: "${currentBuild.getBuildCauses()[0].shortDescription}"

phoenix_tags:
  - key: "image-name"
    value: "${IMAGE_NAME}"
  - key: "commit-sha"
    value: "${GIT_COMMIT.take(7)}"
  - key: "branch"
    value: "${GIT_BRANCH}"
  - key: "ci-system"
    value: "jenkins"
  - key: "pipeline-id"
    value: "${BUILD_NUMBER}"
  - key: "build-date"
    value: "${new Date().format('yyyy-MM-dd')}"
"""
                    writeFile file: 'container_metadata.yaml', text: metadata
                }
            }
        }
        
        stage('Security Scan') {
            steps {
                sh """
                    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \\
                        aquasec/trivy:latest image \\
                        --format json \\
                        --output trivy_results.json \\
                        ${IMAGE_TAG}
                """
            }
        }
        
        stage('Upload to Phoenix') {
            steps {
                script {
                    // Extract phoenix_tags
                    sh """
                        python3 -c "
import yaml
with open('container_metadata.yaml') as f:
    data = yaml.safe_load(f)
with open('phoenix_tags.yaml', 'w') as f:
    yaml.dump(data.get('phoenix_tags', []), f)
"
                    """
                    
                    // Upload to Phoenix
                    withCredentials([usernamePassword(
                        credentialsId: 'phoenix-api-credentials',
                        usernameVariable: 'PHOENIX_CLIENT_ID',
                        passwordVariable: 'PHOENIX_CLIENT_SECRET'
                    )]) {
                        sh """
                            python phoenix_multi_scanner_enhanced.py \\
                                --file trivy_results.json \\
                                --scanner trivy \\
                                --assessment "Jenkins - ${JOB_NAME} - ${BUILD_NUMBER}" \\
                                --tag-file phoenix_tags.yaml
                        """
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: '*.yaml,*.json', fingerprint: true
            cleanWs()
        }
    }
}
```

---

## Azure DevOps

### azure-pipelines.yml Example

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  containerRegistry: 'your-acr.azurecr.io'
  imageName: 'myapp'
  imageTag: '$(containerRegistry)/$(imageName):$(Build.SourceVersion)'

stages:
  - stage: Build
    jobs:
      - job: BuildAndPush
        steps:
          - task: Docker@2
            displayName: 'Build and push image'
            inputs:
              containerRegistry: 'ACR-Connection'
              repository: '$(imageName)'
              command: 'buildAndPush'
              Dockerfile: '**/Dockerfile'
              tags: |
                $(Build.SourceVersion)
                latest

  - stage: Scan
    dependsOn: Build
    jobs:
      - job: SecurityScan
        steps:
          - task: Bash@3
            displayName: 'Generate container metadata'
            inputs:
              targetType: 'inline'
              script: |
                cat > container_metadata.yaml << EOF
                metadata_version: "1.0"
                capture_timestamp: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                
                container:
                  image_full_ref: "$(imageTag)"
                  registry: "$(containerRegistry)"
                  repository: "$(imageName)"
                  image_name: "$(imageName)"
                  tag: "$(Build.SourceVersion)"
                
                source:
                  repository_url: "$(Build.Repository.Uri)"
                  commit_sha: "$(Build.SourceVersion)"
                  commit_sha_short: "$(Build.SourceVersion | cut -c1-7)"
                  branch: "$(Build.SourceBranchName)"
                
                pipeline:
                  ci_system: "azure-devops"
                  pipeline_id: "$(Build.BuildId)"
                  pipeline_url: "$(System.TeamFoundationCollectionUri)$(System.TeamProject)/_build/results?buildId=$(Build.BuildId)"
                  trigger_type: "$(Build.Reason)"
                  trigger_actor: "$(Build.RequestedFor)"
                
                phoenix_tags:
                  - key: "image-name"
                    value: "$(imageName)"
                  - key: "commit-sha"
                    value: "$(Build.SourceVersion)"
                  - key: "branch"
                    value: "$(Build.SourceBranchName)"
                  - key: "ci-system"
                    value: "azure-devops"
                  - key: "pipeline-id"
                    value: "$(Build.BuildId)"
                  - key: "build-date"
                    value: "$(date +%Y-%m-%d)"
                EOF
          
          - task: trivy@1
            displayName: 'Run Trivy scan'
            inputs:
              image: '$(imageTag)'
              format: 'json'
              output: 'trivy_results.json'
          
          - task: PythonScript@0
            displayName: 'Extract Phoenix tags'
            inputs:
              scriptSource: 'inline'
              script: |
                import yaml
                with open('container_metadata.yaml') as f:
                    data = yaml.safe_load(f)
                with open('phoenix_tags.yaml', 'w') as f:
                    yaml.dump(data.get('phoenix_tags', []), f)
          
          - task: Bash@3
            displayName: 'Upload to Phoenix'
            env:
              PHOENIX_CLIENT_ID: $(PHOENIX_CLIENT_ID)
              PHOENIX_CLIENT_SECRET: $(PHOENIX_CLIENT_SECRET)
            inputs:
              targetType: 'inline'
              script: |
                python phoenix_multi_scanner_enhanced.py \
                  --file trivy_results.json \
                  --scanner trivy \
                  --assessment "Azure DevOps - $(Build.DefinitionName) - $(Build.BuildId)" \
                  --tag-file phoenix_tags.yaml
          
          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: '.'
              artifactName: 'security-scan-results'
```

---

## CircleCI

### config.yml Example

```yaml
# .circleci/config.yml
version: 2.1

orbs:
  docker: circleci/docker@2.4.0

executors:
  docker-executor:
    docker:
      - image: cimg/python:3.11

jobs:
  build-and-push:
    executor: docker-executor
    steps:
      - checkout
      - setup_remote_docker:
          version: 20.10.24
      - docker/check
      - docker/build:
          image: $CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME
          tag: $CIRCLE_SHA1
      - docker/push:
          image: $CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME
          tag: $CIRCLE_SHA1

  security-scan:
    executor: docker-executor
    steps:
      - checkout
      - setup_remote_docker:
          version: 20.10.24
      
      - run:
          name: Generate container metadata
          command: |
            cat > container_metadata.yaml << EOF
            metadata_version: "1.0"
            capture_timestamp: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            
            container:
              image_full_ref: "$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME:$CIRCLE_SHA1"
              registry: "docker.io"
              repository: "$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME"
              image_name: "$CIRCLE_PROJECT_REPONAME"
              tag: "$CIRCLE_SHA1"
            
            source:
              repository_url: "https://github.com/$CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME"
              commit_sha: "$CIRCLE_SHA1"
              commit_sha_short: "${CIRCLE_SHA1:0:7}"
              branch: "$CIRCLE_BRANCH"
            
            pipeline:
              ci_system: "circleci"
              pipeline_id: "$CIRCLE_WORKFLOW_ID"
              pipeline_url: "$CIRCLE_BUILD_URL"
              job_id: "$CIRCLE_JOB"
              trigger_actor: "$CIRCLE_USERNAME"
            
            phoenix_tags:
              - key: "image-name"
                value: "$CIRCLE_PROJECT_REPONAME"
              - key: "commit-sha"
                value: "${CIRCLE_SHA1:0:7}"
              - key: "branch"
                value: "$CIRCLE_BRANCH"
              - key: "ci-system"
                value: "circleci"
              - key: "pipeline-id"
                value: "$CIRCLE_WORKFLOW_ID"
              - key: "build-date"
                value: "$(date +%Y-%m-%d)"
            EOF
      
      - run:
          name: Run Trivy scan
          command: |
            docker run --rm \
              -v /var/run/docker.sock:/var/run/docker.sock \
              aquasec/trivy:latest image \
              --format json \
              --output /tmp/trivy_results.json \
              $CIRCLE_PROJECT_USERNAME/$CIRCLE_PROJECT_REPONAME:$CIRCLE_SHA1
            cp /tmp/trivy_results.json .
      
      - run:
          name: Extract Phoenix tags
          command: |
            pip install pyyaml
            python3 << 'EOF'
            import yaml
            with open('container_metadata.yaml') as f:
                data = yaml.safe_load(f)
            with open('phoenix_tags.yaml', 'w') as f:
                yaml.dump(data.get('phoenix_tags', []), f)
            EOF
      
      - run:
          name: Upload to Phoenix
          command: |
            python phoenix_multi_scanner_enhanced.py \
              --file trivy_results.json \
              --scanner trivy \
              --assessment "CircleCI - $CIRCLE_PROJECT_REPONAME - ${CIRCLE_SHA1:0:7}" \
              --tag-file phoenix_tags.yaml
      
      - store_artifacts:
          path: container_metadata.yaml
      - store_artifacts:
          path: trivy_results.json

workflows:
  build-scan-upload:
    jobs:
      - build-and-push
      - security-scan:
          requires:
            - build-and-push
```

---

## Bitbucket Pipelines

### bitbucket-pipelines.yml Example

```yaml
# bitbucket-pipelines.yml
image: python:3.11

definitions:
  services:
    docker:
      memory: 2048

pipelines:
  default:
    - step:
        name: Build and Push
        services:
          - docker
        script:
          - docker build -t $BITBUCKET_REPO_SLUG:$BITBUCKET_COMMIT .
          - docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD
          - docker push $DOCKER_USERNAME/$BITBUCKET_REPO_SLUG:$BITBUCKET_COMMIT
    
    - step:
        name: Security Scan & Upload
        services:
          - docker
        script:
          # Generate metadata
          - |
            cat > container_metadata.yaml << EOF
            metadata_version: "1.0"
            capture_timestamp: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            
            container:
              image_full_ref: "$DOCKER_USERNAME/$BITBUCKET_REPO_SLUG:$BITBUCKET_COMMIT"
              registry: "docker.io"
              repository: "$DOCKER_USERNAME/$BITBUCKET_REPO_SLUG"
              image_name: "$BITBUCKET_REPO_SLUG"
              tag: "$BITBUCKET_COMMIT"
            
            source:
              repository_url: "https://bitbucket.org/$BITBUCKET_WORKSPACE/$BITBUCKET_REPO_SLUG"
              commit_sha: "$BITBUCKET_COMMIT"
              commit_sha_short: "${BITBUCKET_COMMIT:0:7}"
              branch: "$BITBUCKET_BRANCH"
            
            pipeline:
              ci_system: "bitbucket-pipelines"
              pipeline_id: "$BITBUCKET_PIPELINE_UUID"
              pipeline_url: "https://bitbucket.org/$BITBUCKET_WORKSPACE/$BITBUCKET_REPO_SLUG/pipelines/results/$BITBUCKET_BUILD_NUMBER"
            
            phoenix_tags:
              - key: "image-name"
                value: "$BITBUCKET_REPO_SLUG"
              - key: "commit-sha"
                value: "${BITBUCKET_COMMIT:0:7}"
              - key: "branch"
                value: "$BITBUCKET_BRANCH"
              - key: "ci-system"
                value: "bitbucket-pipelines"
              - key: "pipeline-id"
                value: "$BITBUCKET_BUILD_NUMBER"
              - key: "build-date"
                value: "$(date +%Y-%m-%d)"
            EOF
          
          # Run Trivy scan
          - docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --format json -o trivy_results.json $DOCKER_USERNAME/$BITBUCKET_REPO_SLUG:$BITBUCKET_COMMIT
          
          # Extract Phoenix tags
          - pip install pyyaml
          - |
            python3 << 'EOF'
            import yaml
            with open('container_metadata.yaml') as f:
                data = yaml.safe_load(f)
            with open('phoenix_tags.yaml', 'w') as f:
                yaml.dump(data.get('phoenix_tags', []), f)
            EOF
          
          # Upload to Phoenix
          - python phoenix_multi_scanner_enhanced.py --file trivy_results.json --scanner trivy --tag-file phoenix_tags.yaml
        artifacts:
          - container_metadata.yaml
          - trivy_results.json
```

---

## Quick Reference: Environment Variables by CI System

| Variable | GitHub Actions | GitLab CI | Jenkins | Azure DevOps | CircleCI | Bitbucket |
|----------|---------------|-----------|---------|--------------|----------|-----------|
| Commit SHA | `GITHUB_SHA` | `CI_COMMIT_SHA` | `GIT_COMMIT` | `Build.SourceVersion` | `CIRCLE_SHA1` | `BITBUCKET_COMMIT` |
| Branch | `GITHUB_REF_NAME` | `CI_COMMIT_REF_NAME` | `GIT_BRANCH` | `Build.SourceBranchName` | `CIRCLE_BRANCH` | `BITBUCKET_BRANCH` |
| Repo URL | `GITHUB_SERVER_URL`/`GITHUB_REPOSITORY` | `CI_PROJECT_URL` | `GIT_URL` | `Build.Repository.Uri` | - | - |
| Pipeline ID | `GITHUB_RUN_ID` | `CI_PIPELINE_ID` | `BUILD_NUMBER` | `Build.BuildId` | `CIRCLE_WORKFLOW_ID` | `BITBUCKET_BUILD_NUMBER` |
| Actor | `GITHUB_ACTOR` | `GITLAB_USER_LOGIN` | `BUILD_USER` | `Build.RequestedFor` | `CIRCLE_USERNAME` | - |

---

*Last Updated: February 2026*
