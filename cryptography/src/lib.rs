use std::collections::HashMap;
use sha2::{Digest, Sha256, digest};
use digest::generic_array::GenericArray;

pub struct MerkleTreeNode {
    pub hash: GenericArray<u8, <Sha256 as Digest>::OutputSizes>,
    pub left_most_index_covered: u64,
    pub right_most_index_covered: u64,
    pub left_child: Option<Box<MerkleTreeNode>>,
    pub right_child: Option<Box<MerkleTreeNode>>,
    pub encrypted_data: Option<Vec<u8>>,
}

impl MerkleTreeNode {
    pub fn new(left_index_covered: u64, right_index_covered: u64) -> Self {
        MerkleTreeNode {
          hash: Sha256::digest(b""),
          left_most_index_covered: left_index_covered,
          right_most_index_covered: right_index_covered,
        }
    }

    pub fn new_leaf_node(encrypted_data: Vec<u8>, left_index_covered: u64) -> Self {
        MerkleTreeNode {
            hash: Sha256::digest(&encrypted_data),
            left_most_index_covered: left_index_covered,
            right_most_index_covered: left_index_covered,
            encrypted_data: encrypted_data,
        }
    }

    pub fn go_down_and_make_leaf_node(&mut self, to_pos: u64, encrypted_data: Vec<u8>) -> MerkleTreeNode
    {
        if (self.right_most_index_covered - self.left_most_index_covered == 1) {
            // kids are leaves
            if let Some(ref mut child) = self.left_child {
                self.right_child = MerkleTreeNode::new_leaf_node(
                    encrypted_data,
                    child.right_most_index_covered + 1
                )

                self.hash = Sha256::Digest(self.left_child.hash + self.right_child.hash);
            } else {
                self.left_child = MerkleTreeNode::new_leaf_node(
                    encrypted_data,
                    child.right_most_index_covered + 1
                )

                self.hash = Sha256::Digest(self.left_child.hash + self.left_child.hash);
            }

            self
        }
        else {
            if let Some(ref mut child) = self.left_child {
                if (to_pos <= child.right_most_index_covered) {
                    child.go_down_and_make_leaf_node(to_pos, encrypted_data);
                } else {
                    if let Some(ref mut child) = self.right_child {
                        child.go_down_and_make_leaf_node(to_pos, encrypted_data);
                    } else {
                        // skapa right
                        self.right_child = MerkleTreeNode::new(
                            child.right_most_index_covered + 1,
                            self.right_most_index_covered
                        );

                        self.right_child.go_down_and_make_leaf_node(to_pos, encrypted_data);
                    }
                }
            } else {
                // skapa left
                self.right_child = MerkleTreeNode::new(
                    self.left_most_index_covered,
                    self.left_most_index_covered + ((self.right_most_index_covered + 1 - self.left_most_index_covered) / 2)
                );

                self.left_child.go_down_and_make_leaf_node(to_pos, encrypted_data);
            }

            if let Some(ref mut child) = self.right_child {
                self.hash = Sha256::Digest(self.left_child.hash + child.hash);
            } else {
                self.hash = Sha256::Digest(self.left_child.hash + self.left_child.hash);
            }

            self
        }
    }
}

pub struct MerkleTree {
    pub root: Option<MerkleTreeNode>,
    pub leaf_nodes_count: u64,
    pub file_id_to_leaf_id: HashMap<u64, u64>,
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree { 
            root: None, 
            leaf_nodes_count: 0, 
            file_id_to_leaf_id: HashMap::new(),
        }
    }

    pub fn add_leaf_node(&mut self, encrypted_data: Vec<u8>, file_id: u64) -> &MerkleTreeNode
    {
        let leaf_count = self.leaf_nodes_count;

        if (leaf_count == 0) {
            self.root = Some(MerkleTreeNode::new_leaf_node(
              encrypted_data,
              0
            ));

            self.leaf_nodes_count = self.leaf_nodes_count + 1;

            self.file_id_to_leaf_id.insert(file_id, self.leaf_nodes_count - 1);

            self.root.as_ref().unwrap()
        } else {
            // if 2 potens uppdatera rot
            if ((leaf_count & (leaf_count - 1)) == 0) {
                let new_root = MerkleTreeNode::new(0, self.root.right_most_index_covered * 2 + 1);
                new_root.left_child = self.root;

                self.root = new_root;
            }

            self.root.go_down_and_make_leaf_node(self.leaf_nodes_count, encrypted_data);
        }
    }

    pub fn get_leaf_id_from_file_id(&self, file_id: u64) -> Option<u64>
    {
        if let Some(ref mut leaf_id) = self.file_id_to_leaf_id.get(&file_id) {
            Some(leaf_id)
        } else {
            println!("Invlaid file ID.");
            None
        }
    }

    //
}

// verifiera rot = data + hashes // skicka i lista uppåtordning, loopa

// plocka ut data och 

// use hex_literal::hex;
// use sha2::{Sha256, Digest};

// let result = Sha256::digest(b"hello world");
// assert_eq!(result[..], hex!("
//     b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
// ")[..]);
