use crate::storage;
use crate::gcp::GcpService;
use crate::storage::triple_storage::TripleData;
use cait_sith::protocol::Participant;
use cait_sith::triples::TripleShare;
use cait_sith::triples::TriplePub;
use crate::protocol::triple::Triple;

impl GcpService {
    pub async fn test_init(env: String) -> Self {
        let project_id = Some("pagoda-discovery-platform-dev".to_string());
        let storage_options = storage::Options{gcp_project_id: project_id.clone(), sk_share_secret_id:Some("multichain-sk-share-dev-0".to_string()), gcp_datastore_url:None, env: Some(env)};
        GcpService::init(&storage_options).await.unwrap().unwrap()
    }
}

// impl TripleData {
//     pub fn test_new(account_id: String) -> Self {
//         let triple = Triple { 
//             id: 3782733990784086318, 
//             share: TripleShare { 
//                 a: Scalar(Uint(0x6BD0038E0B8C29673692943222264F7161428F60298F7EA805DDE5C1DF212CB2)), 
//                 b: Scalar(Uint(0x7AF0A7F45FF3DEB48CBD429B2279C599622925FD9B0DBFCC09314C70A333A915)), 
//                 c: Scalar(Uint(0xDDB4E55342D0FEFD8E952D8CDCFF736B33634E6F9BEE5F4B5249BB7A3107897A)) 
//             }, 
//             public: TriplePub { 
//                 big_a: AffinePoint { 
//                     x: FieldElement(FieldElementImpl { 
//                         value: FieldElement5x52([4077626281174394, 3754481165830118, 4154111693954253, 1675723372686770, 207759911278305]), 
//                         magnitude: 1, 
//                         normalized: true 
//                     }), 
//                     y: FieldElement(FieldElementImpl { 
//                         value: FieldElement5x52([1806072507508813, 388909146962000, 1664497414208853, 4397753273459762, 29927104822271]), 
//                         magnitude: 1, 
//                         normalized: true 
//                     }), 
//                     infinity: 0 
//                 }, 
//                 big_b: AffinePoint { 
//                     x: FieldElement(FieldElementImpl { 
//                         value: FieldElement5x52([1281368552730675, 1153250914041895, 1080730417247337, 3982126789915841, 210878091306102]), 
//                         magnitude: 1, 
//                         normalized: true 
//                     }), 
//                     y: FieldElement(FieldElementImpl { 
//                         value: FieldElement5x52([2862738944003423, 2437367875321998, 2915557176485883, 610259877360175, 27964283394225]), 
//                         magnitude: 1, 
//                         normalized: true 
//                     }), infinity: 0 
//                 }, 
//                 big_c: AffinePoint { 
//                     x: FieldElement(FieldElementImpl { 
//                         value: FieldElement5x52([2365173768745334, 1357764692133606, 874256395525826, 4427091262890847, 31662670672839]), 
//                         magnitude: 1, 
//                         normalized: true 
//                     }), 
//                     y: FieldElement(FieldElementImpl { 
//                         value: FieldElement5x52([4357430747413447, 2721187911898008, 88218516552092, 2766750897925857, 118728672982746]), 
//                         magnitude: 1, 
//                         normalized: true 
//                     }), 
//                     infinity: 0 
//                 }, 
//                 participants: [Participant(0), Participant(1), Participant(2), Participant(3), Participant(4)], 
//                 threshold: 5 
//             } 
//         };

        
//     }
// }