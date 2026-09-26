import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Any, Optional

class LightweightTransformerSequenceClassifier(nn.Module):
    """
    Lightweight Transformer Sequence Classifier for Encrypted IPsec ESP Packet Streams.
    Input: (B, seq_len, in_dim=4)
    Output:
        - logits: (B, num_classes=4)
        - embedding: (B, embed_dim) for representation analysis & OOD novelty detection
    """

    def __init__(
        self,
        in_dim: int = 4,
        embed_dim: int = 32,
        num_heads: int = 2,
        num_layers: int = 2,
        num_classes: int = 4,
        dropout: float = 0.1
    ):
        super().__init__()
        self.in_proj = nn.Linear(in_dim, embed_dim)
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=64,
            dropout=dropout,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        
        # Temporal attentive pooling
        self.pool_att = nn.Linear(embed_dim, 1)
        self.classifier = nn.Linear(embed_dim, num_classes)

    def forward(
        self,
        x: torch.Tensor,
        mask: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        """
        x: (B, seq_len, in_dim)
        mask: (B, seq_len) True for valid, False for padding
        """
        # Linear projection
        h = self.in_proj(x) # (B, seq_len, embed_dim)
        
        # In PyTorch TransformerEncoder, src_key_padding_mask is True for PADDED tokens
        pad_mask = None
        if mask is not None:
            pad_mask = ~mask # Invert so True = padded
            
        h_enc = self.transformer(h, src_key_padding_mask=pad_mask) # (B, seq_len, embed_dim)
        
        # Attentive sequence pooling
        att_scores = self.pool_att(h_enc).squeeze(-1) # (B, seq_len)
        if mask is not None:
            att_scores = att_scores.masked_fill(~mask, -1e9)
        att_weights = F.softmax(att_scores, dim=-1).unsqueeze(-1) # (B, seq_len, 1)
        
        pooled_embed = torch.sum(h_enc * att_weights, dim=1) # (B, embed_dim)
        logits = self.classifier(pooled_embed) # (B, num_classes)
        
        return {
            "logits": logits,
            "embedding": pooled_embed
        }

class HybridTabularSequenceClassifier(nn.Module):
    """
    Hybrid Classifier combining canonical 14 tabular features with learned Transformer sequence embeddings.
    Input:
        - tabular: (B, 14)
        - sequence: (B, seq_len, 4)
    """

    def __init__(
        self,
        tab_dim: int = 14,
        seq_in_dim: int = 4,
        seq_embed_dim: int = 32,
        num_classes: int = 4
    ):
        super().__init__()
        self.seq_encoder = LightweightTransformerSequenceClassifier(
            in_dim=seq_in_dim,
            embed_dim=seq_embed_dim,
            num_classes=num_classes
        )
        self.tab_proj = nn.Sequential(
            nn.Linear(tab_dim, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(0.1)
        )
        self.fusion_head = nn.Sequential(
            nn.Linear(seq_embed_dim + 32, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes)
        )

    def forward(
        self,
        tab: torch.Tensor,
        seq: torch.Tensor,
        mask: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        seq_res = self.seq_encoder(seq, mask=mask)
        seq_embed = seq_res["embedding"]
        tab_embed = self.tab_proj(tab)
        
        combined = torch.cat([seq_embed, tab_embed], dim=-1)
        logits = self.fusion_head(combined)
        
        return {
            "logits": logits,
            "embedding": combined,
            "seq_embedding": seq_embed
        }

class ProtocolAwareSequenceClassifier(nn.Module):
    """
    Model B2: Protocol-Aware Sequence Transformer.
    Integrates packet temporal dynamics with deterministic protocol/session context features.
    """

    def __init__(
        self,
        seq_in_dim: int = 4,
        context_dim: int = 4,
        embed_dim: int = 32,
        num_classes: int = 4,
        dropout: float = 0.1
    ):
        super().__init__()
        self.seq_encoder = LightweightTransformerSequenceClassifier(
            in_dim=seq_in_dim,
            embed_dim=embed_dim,
            num_classes=num_classes,
            dropout=dropout
        )
        self.context_proj = nn.Sequential(
            nn.Linear(context_dim, 16),
            nn.ReLU()
        )
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim + 16, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes)
        )

    def forward(
        self,
        seq: torch.Tensor,
        context: torch.Tensor,
        mask: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        seq_res = self.seq_encoder(seq, mask=mask)
        seq_embed = seq_res["embedding"] # (B, 32)
        ctx_embed = self.context_proj(context) # (B, 16)
        
        combined = torch.cat([seq_embed, ctx_embed], dim=-1) # (B, 48)
        logits = self.classifier(combined)
        
        return {
            "logits": logits,
            "embedding": combined,
            "seq_embedding": seq_embed
        }

class MultiViewIPsecClassifier(nn.Module):
    """
    Model D: Multi-View IPsec Traffic Classifier.
    Explicitly fuses 3 distinct representation views:
      - View A: Tabular (14 statistical features)
      - View B: Sequence (32 packet temporal dynamics via Transformer)
      - View C: Protocol Context (4 deterministic session/IKE markers)
    """

    def __init__(
        self,
        tab_dim: int = 14,
        seq_in_dim: int = 4,
        context_dim: int = 4,
        seq_embed_dim: int = 32,
        num_classes: int = 4,
        dropout: float = 0.1
    ):
        super().__init__()
        self.seq_encoder = LightweightTransformerSequenceClassifier(
            in_dim=seq_in_dim,
            embed_dim=seq_embed_dim,
            num_classes=num_classes,
            dropout=dropout
        )
        self.tab_encoder = nn.Sequential(
            nn.Linear(tab_dim, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        self.ctx_encoder = nn.Sequential(
            nn.Linear(context_dim, 16),
            nn.ReLU()
        )
        self.fusion_head = nn.Sequential(
            nn.Linear(seq_embed_dim + 32 + 16, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, num_classes)
        )

    def forward(
        self,
        tab: torch.Tensor,
        seq: torch.Tensor,
        context: torch.Tensor,
        mask: Optional[torch.Tensor] = None
    ) -> Dict[str, torch.Tensor]:
        seq_res = self.seq_encoder(seq, mask=mask)
        seq_embed = seq_res["embedding"]
        tab_embed = self.tab_encoder(tab)
        ctx_embed = self.ctx_encoder(context)
        
        fused = torch.cat([seq_embed, tab_embed, ctx_embed], dim=-1) # (B, 80)
        logits = self.fusion_head(fused)
        
        return {
            "logits": logits,
            "embedding": fused,
            "seq_embedding": seq_embed
        }

class MaskedSequencePretrainer(nn.Module):
    """
    Self-Supervised Masked Packet Feature Reconstruction Pretrainer (Model B3).
    Trains an encoder to reconstruct masked packet features (length, IAT) from context.
    """

    def __init__(
        self,
        in_dim: int = 4,
        embed_dim: int = 32,
        num_heads: int = 2,
        num_layers: int = 2
    ):
        super().__init__()
        self.encoder = LightweightTransformerSequenceClassifier(
            in_dim=in_dim,
            embed_dim=embed_dim,
            num_heads=num_heads,
            num_layers=num_layers,
            num_classes=4
        )
        self.reconstruction_head = nn.Sequential(
            nn.Linear(embed_dim, 32),
            nn.ReLU(),
            nn.Linear(32, in_dim)
        )

    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        # Pass through sequence encoder
        h = self.encoder.in_proj(x)
        pad_mask = ~mask if mask is not None else None
        h_enc = self.encoder.transformer(h, src_key_padding_mask=pad_mask)
        recon = self.reconstruction_head(h_enc)
        return recon

