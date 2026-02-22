module cti::cti {
    use std::string::String;
    use sui::event;

    // ==================== Error Codes ====================
    const EInvalidDelegate: u64 = 1;
    const ENotAssignedDelegate: u64 = 3;

    // ==================== Structs ====================

    public struct CTI has key, store {
        id: UID,
        producer: address,
        cti_hash: vector<u8>,          // hash of (CTI|nonce)
        acmp: String,                  // access control metric/policy
        delegates: vector<address>,    // append-only delegates
        encrypted_cti_nft_ids: vector<ID>, // per-delegate EncryptedCTIBlob object IDs
        request_ids: vector<ID>,       // append-only request IDs (kept, even if CLI doesn't read)
    }

    public struct EncryptedCTIBlob has key, store {
        id: UID,
        delegate: address,
        data: String, // pointer (ipfs://... or file://...)
    }

    public struct EncryptedResponseBlob has key, store {
        id: UID,
        request_id: ID,
        delegate: address,
        data: String, // pointer (ipfs://... or file://...)
    }

    public struct CTIRequest has key, store {
        id: UID,
        cti_id: ID,
        consumer: address,
        assigned_delegate: address,
        encrypted_credentials: String,
        encrypted_response_nft_id: Option<ID>,
        response_provided: bool,
    }

    public struct CTIRegistry has key {
        id: UID,
        cti_count: u64,
    }

    // ==================== Events ====================

    public struct CTIShared has copy, drop {
        cti_id: ID,
        producer: address,
        delegate_count: u64,
    }

    public struct CTIRequested has copy, drop {
        request_id: ID,
        cti_id: ID,
        consumer: address,
        assigned_delegate: address,
    }

    public struct CredentialsSubmitted has copy, drop {
        request_id: ID,
        consumer: address,
    }

    public struct ResponseProvided has copy, drop {
        request_id: ID,
        delegate: address,
    }

    // ==================== Initialization ====================

    fun init(ctx: &mut TxContext) {
        let registry = CTIRegistry { id: object::new(ctx), cti_count: 0 };
        transfer::share_object(registry);
    }

    // ==================== Step 2: Share CTI ====================

    public entry fun share_cti(
        registry: &mut CTIRegistry,
        cti_hash: vector<u8>,
        acmp: String,
        delegates: vector<address>,
        mut encrypted_cti_for_delegates: vector<String>,
        ctx: &mut TxContext
    ) {
        let cti_uid = object::new(ctx);
        let cti_id_copy = object::uid_to_inner(&cti_uid);

        let mut blob_ids: vector<ID> = vector::empty();
        let mut i: u64 = 0;
        let n: u64 = vector::length(&encrypted_cti_for_delegates);
        while (i < n) {
            // pop from front to preserve ordering relative to `delegates`
            let enc: String = vector::remove(&mut encrypted_cti_for_delegates, 0);

            let blob_uid = object::new(ctx);
            let blob_id = object::uid_to_inner(&blob_uid);

            let blob = EncryptedCTIBlob {
                id: blob_uid,
                delegate: *vector::borrow(&delegates, i),
                data: enc,
            };
            transfer::share_object(blob);
            vector::push_back(&mut blob_ids, blob_id);

            i = i + 1;
        };

        let cti = CTI {
            id: cti_uid,
            producer: ctx.sender(),
            cti_hash,
            acmp,
            delegates,
            encrypted_cti_nft_ids: blob_ids,
            request_ids: vector::empty(),
        };

        registry.cti_count = registry.cti_count + 1;

        event::emit(CTIShared {
            cti_id: cti_id_copy,
            producer: ctx.sender(),
            delegate_count: vector::length(&cti.delegates),
        });

        transfer::share_object(cti);
    }

    // ==================== Steps 4, 5: Request CTI ====================

    public entry fun request_cti(cti: &mut CTI, ctx: &mut TxContext) {
        let delegate_count = vector::length(&cti.delegates);
        assert!(delegate_count > 0, EInvalidDelegate);

        let request_uid = object::new(ctx);
        let request_id = object::uid_to_inner(&request_uid);

        let random_index = ((object::uid_to_bytes(&request_uid)[0] as u64) % delegate_count);
        let assigned_delegate = *vector::borrow(&cti.delegates, random_index);

        let request = CTIRequest {
            id: request_uid,
            cti_id: object::uid_to_inner(&cti.id),
            consumer: ctx.sender(),
            assigned_delegate,
            encrypted_credentials: std::string::utf8(b""),
            encrypted_response_nft_id: option::none<ID>(),
            response_provided: false,
        };

        vector::push_back(&mut cti.request_ids, request_id);

        event::emit(CTIRequested {
            request_id,
            cti_id: object::uid_to_inner(&cti.id),
            consumer: ctx.sender(),
            assigned_delegate,
        });

        transfer::share_object(request);
    }

    // ==================== Step 6: Submit Credentials ====================

    public entry fun credentials_cti(
        request: &mut CTIRequest,
        encrypted_credentials: String,
        ctx: &mut TxContext
    ) {
        // Only the consumer can submit credentials
        assert!(request.consumer == ctx.sender(), ENotAssignedDelegate);

        request.encrypted_credentials = encrypted_credentials;

        event::emit(CredentialsSubmitted {
            request_id: object::uid_to_inner(&request.id),
            consumer: ctx.sender(),
        });
    }

    // ==================== Steps 7-10: Delegate Response ====================

    public entry fun response_cti(
        request: &mut CTIRequest,
        response_ref: String,
        ctx: &mut TxContext
    ) {
        let blob_uid = object::new(ctx);
        let blob_id = object::uid_to_inner(&blob_uid);

        let blob = EncryptedResponseBlob {
            id: blob_uid,
            request_id: object::uid_to_inner(&request.id),
            delegate: ctx.sender(),
            data: response_ref,
        };
        transfer::share_object(blob);

        request.encrypted_response_nft_id = option::some<ID>(blob_id);
        request.response_provided = true;

        event::emit(ResponseProvided {
            request_id: object::uid_to_inner(&request.id),
            delegate: ctx.sender(),
        });
    }

    // ==================== Step 13: Add Delegate ====================

    public entry fun add_delegate(
        cti: &mut CTI,
        new_delegate: address,
        encrypted_cti_for_new_delegate: String,
        ctx: &mut TxContext
    ) {
        let blob_uid = object::new(ctx);
        let blob_id = object::uid_to_inner(&blob_uid);

        let blob = EncryptedCTIBlob {
            id: blob_uid,
            delegate: new_delegate,
            data: encrypted_cti_for_new_delegate,
        };
        transfer::share_object(blob);

        vector::push_back(&mut cti.delegates, new_delegate);
        vector::push_back(&mut cti.encrypted_cti_nft_ids, blob_id);
    }
}
