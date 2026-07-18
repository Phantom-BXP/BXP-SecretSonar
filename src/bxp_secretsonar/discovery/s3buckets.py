import os
from typing import List
from bxp_secretsonar.discovery.base import DiscoveryProvider

class S3BucketsProvider(DiscoveryProvider):
    name = "s3buckets"

    def __init__(self, aws_access_key=None, aws_secret_key=None, region="us-east-1"):
        self.aws_access_key = aws_access_key or os.environ.get("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = aws_secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        if not self.aws_access_key or not self.aws_secret_key:
            raise ValueError("Credentials AWS manquantes. Définissez AWS_ACCESS_KEY_ID et AWS_SECRET_ACCESS_KEY.")

    async def discover(self, query: str = "", limit: int = 10) -> List[str]:
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError:
            print("[!] boto3 non installé. Installez-le avec 'pip install boto3'")
            return []

        session = boto3.Session(
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key,
            region_name=self.region
        )
        s3 = session.client('s3')
        try:
            response = s3.list_buckets()
            buckets = [b['Name'] for b in response.get('Buckets', [])]
        except ClientError as e:
            print(f"[!] Erreur AWS: {e}")
            return []

        # Pour chaque bucket, vérifier s'il est public (accès non authentifié en lecture)
        urls = []
        for bucket in buckets[:limit]:
            try:
                # Tenter de récupérer l'ACL publique (peut échouer si pas de droit)
                s3.get_bucket_acl(Bucket=bucket)
                urls.append(f"https://{bucket}.s3.amazonaws.com")
            except ClientError:
                pass
        return urls[:limit]
