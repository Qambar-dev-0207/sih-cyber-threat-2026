export type CountermeasureType = 
  | 'iptables' 
  | 'nftables' 
  | 'cisco_acl' 
  | 'dns_rpz' 
  | 'snort3' 
  | 'stix_bundle';

export interface CountermeasureItem {
  countermeasure_type: CountermeasureType;
  target_entity: string;
  artifact_content: string;
  syntax_valid: boolean;
  requires_human_approval: boolean;
  generated_at?: number;
}

export interface StixBundle {
  type: 'bundle';
  id: string;
  spec_version: '2.1';
  objects: Array<{
    type: string;
    id: string;
    created: string;
    modified: string;
    name?: string;
    description?: string;
    pattern?: string;
    pattern_type?: string;
    valid_from?: string;
    [key: string]: any;
  }>;
}
