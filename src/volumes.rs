use log::{debug, info, warn};
use windows::Win32::Storage::FileSystem::PARTITION_BASIC_DATA_GUID;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE, WbemLocator,
};
use windows::core::{BSTR, GUID, w};

fn get_resizable_partitions(server: &IWbemServices) -> anyhow::Result<Vec<(String, BSTR)>> {
    let mut resizable_partitions = Vec::new();

    let query = unsafe {
        server.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(format!("SELECT * FROM MSFT_Partition")),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("Failed to execute WMI query: {e}"))?;

    loop {
        let mut row = [None; 1];
        let mut returned = 0;
        unsafe {
            query
                .Next(WBEM_INFINITE, &mut row, &mut returned)
                .ok()
                .map_err(|e| anyhow::anyhow!("Failed to retrieve next row: {e}"))?
        };

        if row[0].is_none() {
            break;
        }
        let row = row[0].as_ref().unwrap();

        // Check that the partition should be resized
        let mut gpt_type = VARIANT::default();
        unsafe { row.Get(w!("GptType"), 0, &mut gpt_type, None, None) }
            .map_err(|e| anyhow::anyhow!("Failed to get GptType: {e}"))?;

        let gpt_type_str = gpt_type.to_string();
        if gpt_type_str.len() < 38 {
            warn!("Unexpected GptType format: {gpt_type_str}");
            continue;
        }

        let gpt_type_guid = GUID::try_from(&gpt_type_str[1..37])
            .map_err(|e| anyhow::anyhow!("Failed to convert GptType to GUID: {e}"))?;

        if gpt_type_guid != PARTITION_BASIC_DATA_GUID {
            continue; // Skip if not a basic data partition
        }

        // Get the partition letter and base path
        let mut drive_letter = VARIANT::default();
        unsafe { row.Get(w!("DriveLetter"), 0, &mut drive_letter, None, None) }
            .map_err(|e| anyhow::anyhow!("Failed to get DriveLetter: {e}"))?;
        let drive_letter_int: i32 = unsafe { drive_letter.Anonymous.Anonymous.Anonymous.intVal };
        let drive_letter_char = char::from_u32(drive_letter_int as u32)
            .ok_or_else(|| anyhow::anyhow!("Invalid DriveLetter value: {drive_letter_int}"))?;

        let mut base_path = VARIANT::default();
        unsafe { row.Get(w!("__PATH"), 0, &mut base_path, None, None) }
            .map_err(|e| anyhow::anyhow!("Failed to get __PATH: {e}"))?;
        let base_path_bstr = BSTR::from(base_path.to_string());

        resizable_partitions.push((drive_letter_char.to_string(), base_path_bstr));
    }

    Ok(resizable_partitions)
}

fn get_partition_max_size(
    server: &IWbemServices,
    msft_partition_class: &IWbemClassObject,
    partition_path: &BSTR,
) -> anyhow::Result<VARIANT> {
    let get_supported_size_name = BSTR::from("GetSupportedSize");

    let mut get_supported_size_output_signature = None;
    unsafe {
        msft_partition_class.GetMethod(
            &get_supported_size_name,
            0,
            std::ptr::null_mut(),
            &mut get_supported_size_output_signature,
        )
    }
    .map_err(|e| anyhow::anyhow!("Failed to get GetSupportedSize method: {e}"))?;
    get_supported_size_output_signature
        .ok_or_else(|| anyhow::anyhow!("GetSupportedSize output signature was None"))?;

    let mut out_params = None;
    unsafe {
        server.ExecMethod(
            &partition_path,
            &get_supported_size_name,
            Default::default(),
            None,
            None,
            Some(&mut out_params),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("Failed to execute GetSupportedSize method: {e}"))?;

    let out_params =
        out_params.ok_or_else(|| anyhow::anyhow!("Output from GetSupportedSize was None"))?;

    let mut size_max = VARIANT::default();
    unsafe { out_params.Get(w!("SizeMax"), 0, &mut size_max, None, None) }
        .map_err(|e| anyhow::anyhow!("Failed to get SizeMax: {e}"))?;

    Ok(size_max)
}

fn resize_partition(
    server: &IWbemServices,
    msft_partition_class: &IWbemClassObject,
    partition_path: &BSTR,
    new_size: VARIANT,
) -> anyhow::Result<()> {
    let resize_name = BSTR::from("Resize");

    let mut resize_input_signature = None;
    let mut resize_output_signature = None;
    unsafe {
        msft_partition_class.GetMethod(
            &resize_name,
            0,
            &mut resize_input_signature,
            &mut resize_output_signature,
        )
    }
    .map_err(|e| anyhow::anyhow!("Failed to get Resize method: {e}"))?;
    let resize_input_signature =
        resize_input_signature.ok_or_else(|| anyhow::anyhow!("Resize input signature was None"))?;
    resize_output_signature.ok_or_else(|| anyhow::anyhow!("Resize output signature was None"))?;

    let in_params = unsafe { resize_input_signature.SpawnInstance(0) }
        .map_err(|e| anyhow::anyhow!("Failed to spawn Resize input instance: {e}"))?;
    unsafe { in_params.Put(&BSTR::from("Size"), 0, &new_size, 0) }
        .map_err(|e| anyhow::anyhow!("Failed to set Size in Resize input: {e}"))?;

    let mut out_params = None;
    unsafe {
        server.ExecMethod(
            &partition_path,
            &resize_name,
            Default::default(),
            None,
            Some(&in_params),
            Some(&mut out_params),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("Failed to execute Resize method: {e}"))?;

    Ok(())
}

pub fn extend_partitions() -> anyhow::Result<()> {
    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| anyhow::anyhow!("Failed to create WbemLocator instance: {e}"))?;

    let server = unsafe {
        locator.ConnectServer(
            &BSTR::from("ROOT\\Microsoft\\Windows\\Storage"),
            &BSTR::default(),
            &BSTR::default(),
            &BSTR::default(),
            0,
            &BSTR::default(),
            None,
        )
    }
    .map_err(|e| anyhow::anyhow!("Failed to connect to WMI server: {e}"))?;

    let class_name = BSTR::from("MSFT_Partition");

    let mut msft_partition_class = None;
    unsafe {
        server
            .GetObject(
                &class_name,
                Default::default(),
                None,
                Some(&mut msft_partition_class),
                None,
            )
            .map_err(|e| anyhow::anyhow!("Failed to get MSFT_Partition class: {e}"))?
    }
    let msft_partition_class =
        msft_partition_class.ok_or_else(|| anyhow::anyhow!("MSFT_Partition class was None"))?;

    debug!("Retrieving resizable partitions");

    let resizable_partitions = get_resizable_partitions(&server)
        .map_err(|e| anyhow::anyhow!("Failed to get resizable partitions: {e}"))?;

    for (partition_name, partition_path) in resizable_partitions {
        debug!("Processing partition: {partition_name}");

        let size_max = get_partition_max_size(&server, &msft_partition_class, &partition_path)
            .map_err(|e| anyhow::anyhow!("Failed to get partition max size: {e}"))?;

        debug!("Max size for partition {partition_name}: {size_max}");

        resize_partition(&server, &msft_partition_class, &partition_path, size_max)
            .map_err(|e| anyhow::anyhow!("Failed to resize partition: {e}"))?;

        info!("Successfully resized partition: {partition_name}");
    }

    Ok(())
}
