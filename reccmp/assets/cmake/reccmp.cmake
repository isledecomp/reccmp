# Find reccmp-ghidra-import for adding reccmp-import-ghidra-<ID> build targets
find_program(RECCMP_GHIDRA_IMPORT_BIN
    NAMES reccmp-ghidra-import
    DOC "Path of reccmp-ghidra-import"
)
if(EXISTS "${RECCMP_GHIDRA_IMPORT_BIN}")
    # Avoid running multiple reccmp-ghidra-import in parallel
    set_property(GLOBAL APPEND PROPERTY JOB_POOLS "reccmp_import_ghidra_job_pool=1")
    add_custom_target(reccmp-import-ghidra)
endif()

function(reccmp_find_project RESULT)
    set(curdir "${CMAKE_CURRENT_SOURCE_DIR}")
    while(1)
        if(EXISTS "${curdir}/reccmp-project.yml")
            break()
        endif()
        get_filename_component(nextdir "${curdir}" DIRECTORY)
        if(nextdir STREQUAL curdir)
            set(curdir "${RESULT}-NOTFOUND")
            break()
        endif()
        set(curdir "${nextdir}")
    endwhile()
    set("${RESULT}" "${curdir}" PARENT_SCOPE)
endfunction()

function(reccmp_add_target TARGET)
    cmake_parse_arguments(ARGS "" "ID" "" ${ARGN})
    if(NOT ARGS_ID)
        message(FATAL_ERROR "Missing ID argument")
    endif()
    set_property(TARGET ${TARGET} PROPERTY INTERFACE_RECCMP_ID "${ARGS_ID}")
    set_property(GLOBAL APPEND PROPERTY RECCMP_TARGETS ${TARGET})
    if(EXISTS "${RECCMP_GHIDRA_IMPORT_BIN}")
        set(RECCMP_${ARGS_ID}_GHIDRA_LOCAL_PROJECT_PATH "" CACHE FILEPATH "Path of Ghidra ${ARGS_ID} project, e.g. '/some-dir/foo.gpr'.")
        set(RECCMP_${ARGS_ID}_GHIDRA_FILE "" CACHE STRING "Name of the file inside the Ghidra project, e.g. '/foo.exe'.")
        if(EXISTS "${RECCMP_${ARGS_ID}_GHIDRA_LOCAL_PROJECT_PATH}" AND NOT "${RECCMP_${ARGS_ID}_GHIDRA_FILE}" STREQUAL "")
            get_filename_component(ghidra_project_dir "${RECCMP_${ARGS_ID}_GHIDRA_LOCAL_PROJECT_PATH}" DIRECTORY)
            get_filename_component(ghidra_project_name "${RECCMP_${ARGS_ID}_GHIDRA_LOCAL_PROJECT_PATH}" NAME_WE)
            add_custom_target(reccmp-import-ghidra-${ARGS_ID}
                COMMAND "${RECCMP_GHIDRA_IMPORT_BIN}"
                    --target "${ARGS_ID}"
                    --local-project-dir "${ghidra_project_dir}"
                    --local-project-name "${ghidra_project_name}"
                    --file "${RECCMP_${ARGS_ID}_GHIDRA_FILE}"
                JOB_POOL "reccmp_import_ghidra_job_pool"
                WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
            )
            add_dependencies(reccmp-import-ghidra reccmp-import-ghidra-${ARGS_ID})
        endif()
    endif()
endfunction()

function(reccmp_configure)
    cmake_parse_arguments(ARGS "COPY_TO_SOURCE_FOLDER" "DIR" "" ${ARGN})
    set(binary_dir "${CMAKE_BINARY_DIR}")
    if(ARGS_DIR)
        set(binary_dir "${ARGS_DIR}")
    endif()

    reccmp_find_project(reccmp_project_dir)
    if(NOT reccmp_project_dir)
        message(FATAL_ERROR "Cannot find reccmp-project.yml")
    endif()

    if(CMAKE_CONFIGURATION_TYPES)
        set(outputdir "${binary_dir}/$<CONFIG>")
    else()
        set(outputdir "${binary_dir}")
    endif()
    set(build_yml_txt "project: '${reccmp_project_dir}'\ntargets:\n")
    get_property(RECCMP_TARGETS GLOBAL PROPERTY RECCMP_TARGETS)
    foreach(target ${RECCMP_TARGETS})
        get_property(id TARGET "${target}" PROPERTY INTERFACE_RECCMP_ID)
        string(APPEND build_yml_txt "  ${id}:\n")
        string(APPEND build_yml_txt "    path: '$<TARGET_FILE:${target}>'\n")
        if(WIN32 AND MSVC)
            string(APPEND build_yml_txt "    pdb: '$<TARGET_PDB_FILE:${target}>'\n")
        endif()
    endforeach()
    file(GENERATE OUTPUT "${outputdir}/reccmp-build.yml" CONTENT "${build_yml_txt}")

    if(ARGS_COPY_TO_SOURCE_FOLDER)
        file(GENERATE OUTPUT "${CMAKE_SOURCE_DIR}/reccmp-build.yml" CONTENT "${build_yml_txt}" CONDITION $<CONFIG:Release>)
    endif()
endfunction()
